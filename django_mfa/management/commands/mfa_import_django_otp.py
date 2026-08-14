"""Import factors from django-otp (and therefore django-two-factor-auth).

django-two-factor-auth needs no importer of its own: it stores its TOTP and
static tokens as django-otp rows (``django_otp.plugins.otp_totp.TOTPDevice``,
``django_otp.plugins.otp_static.StaticDevice``/``StaticToken``), so this
command covers both. Its own ``PhoneDevice`` rows (SMS/call) have no
counterpart in django_mfa and are not handled here -- that model lives in
django-two-factor-auth's own ``two_factor`` app, which is not part of the
django-otp dependency this command resolves through ``apps.get_model()``, so
those rows are simply left untouched rather than guessed at.
"""

import base64

from django.apps import apps
from django.contrib.auth.hashers import make_password
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from django_mfa.conf import settings as mfa_settings
from django_mfa.crypto import encrypt
from django_mfa.models import Authenticator
from django_mfa.registry import registry
from django_mfa.utils import user_email

#: django_mfa.totp is fixed at these. A device that differs cannot be
#: represented, and importing it would produce a factor whose codes never
#: match -- a lockout the user discovers, not the operator.
#:
#: `drift` belongs here even though it looks like verification-only state:
#: django_otp.oath.TOTP.t() adds it directly into the counter
#: (`((time - t0) // step) + drift`), so a drift of k is mathematically the
#: same shift as a t0 of `-k * step` -- and unlike t0, it is not something an
#: operator would think to check, because it is not part of enrolment. It
#: *accumulates*: TOTPDevice.verify_token() saves a new drift on every
#: successful verification whenever OTP_TOTP_SYNC is on, which is
#: django-otp's default. A user whose phone clock runs fast gains drift on
#: every login, silently compensated by django-otp forever -- import that
#: device without checking drift and it "imports clean" while the user's
#: codes land outside django_mfa's fixed +/-1 step window from the next
#: login onward.
#:
#: `tolerance` is the sibling of django_mfa's own TOTP_VALID_WINDOW = 1 --
#: TOTPDevice.verify_token() calls totp.verify(token, self.tolerance, ...),
#: so it is django-otp's acceptance window in units of steps either side of
#: current, the exact quantity the mfa_import_django_mfa2 importer devotes a
#: standing warning to because it *cannot* be checked per row there.
#: TOTPDevice.tolerance defaults to 1 (verified against the installed
#: django-otp's TOTPDevice model), matching django_mfa exactly -- but it is
#: a stored, per-device field an operator could have widened, and unlike
#: mfa2's importer this one CAN check it per row, so it does: a
#: TOTPDevice(tolerance=5) would otherwise "import clean" and then narrow
#: silently, exactly the failure mode `drift` above exists to catch.
SUPPORTED_TOTP = {"digits": 6, "step": 30, "t0": 0, "drift": 0, "tolerance": 1}


def _get_model(app_label, model_name):
    try:
        return apps.get_model(app_label, model_name)
    except LookupError:
        return None


class Command(BaseCommand):
    help = ("Import TOTP, static-token (recovery code) and email factors "
           "from django-otp.")

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true",
                            help="report what would happen; write nothing")
        parser.add_argument("--users", nargs="+", metavar="USER",
                            help="limit to these usernames or pks")
        parser.add_argument("--overwrite", action="store_true",
                            help="replace an existing factor of the same type")

    def handle(self, *args, **options):
        totp_model = _get_model("otp_totp", "TOTPDevice")
        static_model = _get_model("otp_static", "StaticDevice")
        email_model = _get_model("otp_email", "EmailDevice")
        if totp_model is None and static_model is None and email_model is None:
            raise CommandError(
                "No django-otp models found. Add 'django_otp' and its plugin "
                "apps (otp_totp, otp_static, otp_email) to INSTALLED_APPS, or "
                "run this on the deployment that still has them."
            )

        self.dry_run = options["dry_run"]
        self.overwrite = options["overwrite"]
        # Every line this command prints while it's not actually writing
        # must say so -- not just the final summary. Without this, a real
        # cutover's per-row "imported ... for ..." lines are indistinguishable
        # from a --dry-run rehearsal's once the summary has scrolled off, and
        # an operator reads a run that wrote nothing as though it had.
        self.prefix = "[dry run] " if self.dry_run else ""
        self.counts = {"imported": 0, "skipped_existing": 0,
                       "skipped_unsupported": 0}
        # What this run has already decided for a given (user, factor type)
        # -- imported OR skipped-as-existing both count. Without this, a
        # second confirmed source device of the same type for the same user
        # (django-otp puts no uniqueness constraint on Device.user, so this
        # is a legal, real-world state after a re-enrolment that never
        # cleaned up its old device) would be evaluated against whatever
        # _write() had already committed and, under --overwrite, silently
        # replace it -- non-deterministically, since neither queryset below
        # was ordered, so which device "won" depended on what the database
        # felt like returning first.
        self._seen = set()
        self._registered_types = {a.type for a in registry.all()}
        users = self._users(options["users"])

        with transaction.atomic():
            if totp_model is not None:
                self._import_totp(totp_model, users)
            if static_model is not None:
                self._import_static(static_model, users)
            if email_model is not None:
                self._import_email(email_model, users)
            if self.dry_run:
                transaction.set_rollback(True)

        self._report()

    def _users(self, identifiers):
        if not identifiers:
            return None
        from django_mfa.management.commands._support import resolve_user
        return [resolve_user(i) for i in identifiers]

    def _filter(self, queryset, users):
        return queryset if users is None else queryset.filter(user__in=users)

    def _write(self, user, factor_type, data, name=""):
        """Create the row unless one exists, honouring --overwrite.

        Refuses to write a type nothing on this install can ever verify
        with, and refuses to let a second source device for the same
        (user, factor_type) overwrite what an earlier device in this same
        run already decided -- see the two comments below for why each
        matters.
        """
        if factor_type not in self._registered_types:
            # MFA_FACTORS excludes this type (email is off by default; a
            # host project can drop recovery_codes or totp too), so nothing
            # will ever offer or verify this row -- it would sit in the
            # database looking like protection while
            # registry.has_primary_factor(user) stays False and the user is
            # bounced to enrolment. Naming MFA_FACTORS is the point: this is
            # the one setting an operator can change and re-run against.
            self.counts["skipped_unsupported"] += 1
            self.stdout.write(self.style.WARNING(
                # str(factor_type), not !r: Authenticator.Type is a
                # TextChoices (str subclass) whose repr is the noisy
                # "Authenticator.Type.EMAIL" rather than plain "email" --
                # str() gives the value an operator can paste straight into
                # MFA_FACTORS.
                f"{self.prefix}  skipped {user}: no adapter is registered "
                f"for '{factor_type}' on this install (MFA_FACTORS="
                f"{list(mfa_settings.MFA_FACTORS)!r}) -- the row would be "
                f"inert. Add '{factor_type}' to MFA_FACTORS and re-run."))
            return

        key = (user.pk, factor_type)
        if key in self._seen:
            self.counts["skipped_unsupported"] += 1
            self.stdout.write(self.style.WARNING(
                f"{self.prefix}  skipped {user}: a second confirmed "
                f"{factor_type} source device was found for this user in "
                f"the same run. django_mfa holds one {factor_type} factor "
                f"per user, so only the first (ordered by pk) was "
                f"considered -- this one was left out rather than silently "
                f"overwriting it. Remove the stale source device and "
                f"re-run if the discarded one should have won instead."))
            return
        self._seen.add(key)

        existing = Authenticator.objects.filter(user=user, type=factor_type)
        if existing.exists():
            if not self.overwrite:
                self.counts["skipped_existing"] += 1
                self.stdout.write(
                    f"{self.prefix}  skipped {user}: already has a "
                    f"{factor_type} factor")
                return
            existing.delete()
        # Deliberately no events.factor_added: with MFA_NOTIFY_ON_CHANGE on,
        # a bulk import would mail every migrated user "a factor was added"
        # on cutover day. This is a migration of a factor they already have,
        # not the addition of a new one.
        Authenticator.objects.create(
            user=user, type=factor_type, data=data, name=name)
        self.counts["imported"] += 1
        self.stdout.write(f"{self.prefix}  imported {factor_type} for {user}")

    def _import_totp(self, model, users):
        query = model.objects.filter(confirmed=True).order_by("pk")
        for device in self._filter(query, users):
            # No default on getattr(): a field SUPPORTED_TOTP names must
            # exist on the installed django-otp's TOTPDevice, or this check
            # -- the one check whose entire purpose is preventing a silent
            # bad import -- would itself silently pass a device it cannot
            # actually evaluate. Let a missing field raise loudly instead.
            mismatched = [
                field for field, expected in SUPPORTED_TOTP.items()
                if getattr(device, field) != expected
            ]
            if mismatched:
                self.counts["skipped_unsupported"] += 1
                self.stdout.write(self.style.WARNING(
                    f"{self.prefix}  skipped {device.user}: TOTP device "
                    f"uses non-default {', '.join(mismatched)} — django_mfa "
                    f"is fixed at 6 digits, a 30-second step, T0=0, a +/-1 "
                    f"step acceptance window, and no stored clock-drift "
                    f"compensation, so importing it would produce codes "
                    f"that never match or accept a narrower window than "
                    f"the user is used to. Re-enrol this user with a fresh "
                    f"authenticator app entry instead."))
                continue
            # TOTPDevice.key is hex; django_mfa.totp secrets are base32.
            secret = base64.b32encode(bytes.fromhex(device.key)).decode("utf-8")
            self._write(device.user, Authenticator.Type.TOTP,
                        {"secret": encrypt(secret)})

    def _import_static(self, model, users):
        # confirmed=True, matching _import_totp/_import_email: StaticDevice
        # inherits `confirmed` from django_otp's abstract Device model same as
        # the other two, and an unconfirmed device is one the user never
        # finished setting up.
        query = model.objects.filter(confirmed=True).order_by("pk")
        for device in self._filter(query, users):
            tokens = list(device.token_set.values_list("token", flat=True))
            if not tokens:
                continue
            # Hashed on the way in, exactly as RecoveryCodesAdapter.generate
            # writes them -- so the codes the user has already printed keep
            # working, and nothing lands in the database in plaintext. NOT
            # the migrated_plaintext path adapters/recovery_codes.py still
            # carries for legacy rows -- these codes were never plaintext
            # here to begin with.
            self._write(device.user, Authenticator.Type.RECOVERY_CODES,
                        {"codes": [make_password(t) for t in tokens],
                         "used": []})

    def _import_email(self, model, users):
        query = model.objects.filter(confirmed=True).order_by("pk")
        for device in self._filter(query, users):
            # user_email(), not a hardcoded device.user.email -- AUTH_USER_
            # MODEL is swappable and need not call its address field
            # "email" at all (see utils.user_email's own docstring);
            # EmailAdapter itself never reads the raw attribute either.
            address = getattr(device, "email", None) or user_email(device.user)
            if not address:
                self.counts["skipped_unsupported"] += 1
                self.stdout.write(self.style.WARNING(
                    f"{self.prefix}  skipped {device.user}: email device "
                    f"has no address of its own and the user has none on "
                    f"file either."))
                continue
            self._write(device.user, Authenticator.Type.EMAIL,
                        {"address": address})

    def _report(self):
        self.stdout.write(self.style.SUCCESS(
            f"{self.prefix}imported {self.counts['imported']}, "
            f"skipped {self.counts['skipped_existing']} already present, "
            f"skipped {self.counts['skipped_unsupported']} unrepresentable."))
