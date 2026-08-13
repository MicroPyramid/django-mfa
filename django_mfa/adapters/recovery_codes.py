# django_mfa/adapters/recovery_codes.py
import secrets
import string

from django.contrib.auth.hashers import check_password, make_password

from django_mfa import events
from django_mfa.atomic import update_data
from django_mfa.models import Authenticator
from django_mfa.registry import Adapter
from django_mfa.utils import strings_equal

CODE_COUNT = 10
CODE_LENGTH = 10
ALPHABET = string.ascii_letters + string.digits


class RecoveryCodesAdapter(Adapter):
    type = Authenticator.Type.RECOVERY_CODES
    verbose_name = "Recovery codes"
    # Recovery codes are exhaustible and must never be a user's sole second
    # factor. They still appear in the verification picker (you can verify with
    # one), but must not make primary_enabled_for() non-empty.
    counts_as_primary_factor = False
    # Recovery codes are generated at mfa:recovery_codes, not enrolled: this
    # adapter implements no begin_enroll/complete_enroll, so it must never be
    # offered as something to "add" (see Registry.available_for).
    supports_enroll = False

    def generate(self, user):
        codes = []
        while len(codes) < CODE_COUNT:
            code = "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))
            if code not in codes:
                codes.append(code)
        Authenticator.objects.filter(user=user, type=self.type).delete()
        Authenticator.objects.create(
            user=user, type=self.type,
            data={"codes": [make_password(c) for c in codes], "used": []},
        )
        return codes  # plaintext, shown to the user exactly once

    def remaining(self, user):
        auth = self.get_instances(user).first()
        if auth is None:
            return 0
        return len(auth.data.get("codes", [])) - len(auth.data.get("used", []))

    def begin_verify(self, request, user):
        return {"remaining": self.remaining(user)}

    def complete_verify(self, request, user, data):
        auth = self.get_instances(user).first()
        if auth is None:
            return False
        submitted = data.get("code", "")

        def spend(current):
            """Match and mark one code, against the blob as committed.

            Deliberately does the matching *inside* the compare-and-set
            rather than before it: the `used` set this consults has to be the
            one the write is conditioned on, or a code another request spent
            microseconds ago still reads as unspent here. Returning None
            declines the write, which update_data() reports as a failed
            verification.
            """
            used = set(current.get("used", []))
            plaintext = current.get("migrated_plaintext", False)
            for index, stored in enumerate(current.get("codes", [])):
                if index in used:
                    continue
                matched = (strings_equal(stored, submitted) if plaintext
                           else check_password(submitted, stored))
                if matched:
                    return {**current, "used": sorted(used | {index})}
            return None

        if not update_data(auth, spend):
            return False
        auth.record_usage()
        events.recovery_code_used.send_robust(
            sender=type(self), user=user,
            remaining=self.remaining(user), request=request)
        return True
