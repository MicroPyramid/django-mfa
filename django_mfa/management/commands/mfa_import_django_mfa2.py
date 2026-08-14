"""Import factors from django-mfa2 (``mfa.models.User_Keys``).

django-mfa2 keys rows by *username string*, not a foreign key, so a row
whose username no longer resolves to a user is reported rather than
silently dropped.

That username string is NOT reliably ``get_user_model().USERNAME_FIELD``,
which is why the matching below tries it and then falls back to a literal
``username`` attribute rather than deriving purely from USERNAME_FIELD the
way ``mfa_import_django_otp`` and ``_support.resolve_user`` do. Checked
against the installed django-mfa2: every TOTP-writing call site
(``mfa/totp.py:84``) and the RECOVERY/U2F/FIDO2/Trusted-Device ones
(``recovery.py:54``, ``U2F.py:163``, ``FIDO2.py:118``,
``TrustedDevice.py:116``) write ``request.user.username`` -- the literal
attribute -- while ``Email.py``'s *enrolment* path (``start()``, line 42)
writes ``getattr(request.user, USERNAME_FIELD)`` instead. django-mfa2 is
not internally consistent about this, so on the default user model
(``USERNAME_FIELD == "username"``) the two always agree and nothing here
matters; on a swapped ``AUTH_USER_MODEL`` they can name different users,
and TOTP -- the row type this command actually cares most about --
consistently uses the literal attribute. Trying USERNAME_FIELD first
preserves the one write path that does use it, falling back to plain
``username`` covers every other path including all of TOTP.

Only TOTP and email are migrated -- see the task this command was written
for. ``User_Keys.key_type`` has four other real values, all handled
explicitly rather than falling through a generic "unrecognised" branch:

* ``FIDO2`` / ``U2F`` -- genuinely no counterpart here. Both would need the
  source package's own WebAuthn credential/user-handle state to keep
  working, which this command has no way to carry over.
* ``Trusted Device`` -- a browser-remembered-device cookie feature with no
  django_mfa equivalent at all.
* ``RECOVERY`` -- django_mfa *does* have a counterpart
  (``Authenticator.Type.RECOVERY_CODES``), but converting it is out of this
  command's scope (TOTP + email only); reported distinctly from the three
  above so the message doesn't claim "no counterpart" for something that in
  fact has one.

Parameter check for TOTP *generation* (see the ``mfa_import_django_otp``
sibling command for the shape of this problem, where django-otp's
``TOTPDevice.drift`` was missed on the first pass and produced silent
lockouts): django-mfa2's own TOTP flow (``mfa/totp.py``, the only code
that ever writes a ``TOTP`` ``User_Keys`` row) always calls
``pyotp.TOTP(secret_key)`` with no ``digits``/``digest``/``interval``
override, and ``properties`` never holds anything for a TOTP row besides
``secret_key``. pyotp's own defaults (6 digits, SHA1, a 30-second interval)
already match django_mfa's fixed parameters, and pyotp's
``TOTP.timecode()`` is `int(unix_time / interval)` -- no ``t0`` offset and
no persisted ``drift`` exist in pyotp's model at all, let alone in what
``User_Keys`` stores. There is therefore nothing to validate on the
*generation* side, for any row: every enabled TOTP row is representable, or
its secret is simply missing. The secret itself needs no format conversion
either -- ``pyotp.random_base32()`` (``mfa/totp.py``'s ``getToken``)
produces the same base32 text ``django_mfa.otp.OTP.byte_secret`` expects,
unlike django-otp's hex-stored key.

The *acceptance* side is a different, unconditional mismatch that no
per-row check can catch or skip around: ``mfa/totp.py``'s own verification
(line 24, ``totp.verify(token, valid_window=30)``) accepts a code up to 30
pyotp ``valid_window`` ticks either side of the current one -- pyotp counts
that argument in whole *steps* (30s each), so mfa2 has been accepting codes
up to +/-15 minutes out of step. django_mfa's ``TOTP_VALID_WINDOW = 1`` is
+/-30 seconds, a 30x narrower acceptance window. A user whose device clock
has drifted several minutes (mfa2 never *stores* that drift -- it just
tolerates it fresh on every check) will have logged in successfully under
mfa2 for as long as they liked and will be silently locked out under
django_mfa from the very first login after import, with no signal to the
operator that anything is wrong: the secret imported byte-perfect and the
summary says "imported". This is announced once, unconditionally, in the
command's own summary output rather than attempted per-row, precisely
because whether a given user's clock is skewed enough to matter cannot be
determined from anything ``User_Keys`` stores.
"""

from django.apps import apps
from django.contrib.auth import get_user_model
from django.core.exceptions import FieldError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from django_mfa.conf import settings as mfa_settings
from django_mfa.crypto import encrypt
from django_mfa.models import Authenticator
from django_mfa.registry import registry
from django_mfa.utils import user_email

#: key_type -> our factor type. The only two key_types this command migrates.
MIGRATABLE = {"TOTP": Authenticator.Type.TOTP, "Email": Authenticator.Type.EMAIL}

#: No django_mfa counterpart at all.
NO_COUNTERPART = ("FIDO2", "U2F", "Trusted Device")

#: Has a django_mfa counterpart (recovery_codes) but converting it is out of
#: this command's scope -- reported separately from NO_COUNTERPART so the
#: message is accurate.
OUT_OF_SCOPE = ("RECOVERY",)


def _get_model():
    try:
        return apps.get_model("mfa", "User_Keys")
    except LookupError:
        return None


class Command(BaseCommand):
    help = "Import TOTP and email factors from django-mfa2."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true",
                            help="report what would happen; write nothing")
        parser.add_argument("--users", nargs="+", metavar="USER",
                            help="limit to these usernames or pks")
        parser.add_argument("--overwrite", action="store_true",
                            help="replace an existing factor of the same type")

    def handle(self, *args, **options):
        model = _get_model()
        if model is None:
            raise CommandError(
                "django-mfa2 is not installed, or 'mfa' is not in "
                "INSTALLED_APPS. Run this on the deployment that still has "
                "it."
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
                       "skipped_unsupported": 0, "unknown_user": 0}
        # What this run has already decided for a given (user, factor type)
        # -- imported OR skipped-as-existing both count. django-mfa2 puts no
        # uniqueness constraint on User_Keys, so one user can hold several
        # enabled rows of the same key_type; without this, a second row
        # would be evaluated against whatever _write() already committed
        # and, under --overwrite, silently replace it -- non-deterministically,
        # since the queryset below is what decides which row is seen first.
        self._seen = set()
        self._registered_types = {a.type for a in registry.all()}

        user_model = get_user_model()
        field = user_model.USERNAME_FIELD
        usernames = None
        if options["users"]:
            from django_mfa.management.commands._support import resolve_user
            # Both possible values a User_Keys row could have been written
            # with (see the module docstring) -- USERNAME_FIELD for a row
            # from Email.py's enrolment path, literal `username` for every
            # other write site including all of TOTP. On the default user
            # model these coincide, so this is a no-op there.
            usernames = set()
            for identifier in options["users"]:
                resolved = resolve_user(identifier)
                usernames.add(getattr(resolved, field))
                literal = getattr(resolved, "username", None)
                if literal:
                    usernames.add(literal)

        query = model.objects.filter(enabled=True).order_by("pk")
        if usernames is not None:
            query = query.filter(username__in=usernames)

        with transaction.atomic():
            for row in query:
                self._import_row(row, user_model, field)
            if self.dry_run:
                transaction.set_rollback(True)

        self._report()

    def _find_user(self, user_model, field, source_username):
        """Resolve one User_Keys.username value to a user on this install.

        Tries USERNAME_FIELD first (correct for a row written by
        Email.py's enrolment path), then falls back to a literal
        `username` attribute (what every other django-mfa2 write site
        uses, including all of TOTP) -- see the module docstring for why
        neither alone is reliable on a swapped AUTH_USER_MODEL. On the
        default user model `field == "username"`, so the fallback is
        never reached and this is exactly the single query it always was.
        """
        user = user_model.objects.filter(**{field: source_username}).first()
        if user is not None or field == "username":
            return user
        try:
            return user_model.objects.filter(username=source_username).first()
        except FieldError:
            # This user model has no field literally called "username" at
            # all (a fully custom AUTH_USER_MODEL) -- nothing more to try.
            return None

    def _import_row(self, row, user_model, field):
        if row.key_type in NO_COUNTERPART:
            self.counts["skipped_unsupported"] += 1
            self.stdout.write(self.style.WARNING(
                f"{self.prefix}  skipped {row.username}: {row.key_type} has "
                f"no counterpart in django_mfa; that user must re-enrol."))
            return
        if row.key_type in OUT_OF_SCOPE:
            self.counts["skipped_unsupported"] += 1
            self.stdout.write(self.style.WARNING(
                f"{self.prefix}  skipped {row.username}: {row.key_type} has "
                f"a django_mfa counterpart (recovery_codes) but this "
                f"command migrates TOTP and email only -- not imported. "
                f"That user should generate fresh recovery codes from "
                f"django_mfa's security settings page once they hold a "
                f"primary factor again."))
            return
        factor_type = MIGRATABLE.get(row.key_type)
        if factor_type is None:
            self.counts["skipped_unsupported"] += 1
            self.stdout.write(self.style.WARNING(
                f"{self.prefix}  skipped {row.username}: unrecognised "
                f"key_type {row.key_type!r}"))
            return

        user = self._find_user(user_model, field, row.username)
        if user is None:
            self.counts["unknown_user"] += 1
            self.stdout.write(self.style.WARNING(
                f"{self.prefix}  no user matches {row.username!r}; row "
                f"left alone"))
            return

        if factor_type == Authenticator.Type.TOTP:
            properties = row.properties or {}
            secret = properties.get("secret_key")
            if not secret:
                self.counts["skipped_unsupported"] += 1
                self.stdout.write(self.style.WARNING(
                    f"{self.prefix}  skipped {user}: TOTP row has no "
                    f"secret_key"))
                return
            data = {"secret": encrypt(secret)}
        else:
            # mfa2 stores no per-key address for an Email row (Email.py's
            # `start` view never sets `properties` at all): sendEmail()
            # always targets the account's own address, so that is the only
            # source, unlike django-otp's EmailDevice which carries its own
            # optional address field. user_email() rather than a hardcoded
            # `user.email` -- AUTH_USER_MODEL is swappable and need not call
            # its address field "email" at all (see utils.user_email's own
            # docstring); EmailAdapter itself never reads the raw attribute.
            address = user_email(user)
            if not address:
                self.counts["skipped_unsupported"] += 1
                self.stdout.write(self.style.WARNING(
                    f"{self.prefix}  skipped {user}: no email address is "
                    f"on file for this user; mfa2 always sends to the "
                    f"account's own address, so nothing can be migrated."))
                return
            data = {"address": address}

        self._write(user, factor_type, data)

    def _write(self, user, factor_type, data):
        """Create the row unless one exists, honouring --overwrite.

        Refuses to write a type nothing on this install can ever verify
        with, and refuses to let a second source row for the same (user,
        factor_type) overwrite what an earlier row in this same run already
        decided.
        """
        if factor_type not in self._registered_types:
            # MFA_FACTORS excludes this type (email is off by default) --
            # nothing will ever offer or verify this row, so it would sit in
            # the database looking like protection while
            # registry.has_primary_factor(user) stays False and the user is
            # bounced to enrolment. Naming MFA_FACTORS is the point: it's
            # the one setting an operator can change and re-run against.
            self.counts["skipped_unsupported"] += 1
            self.stdout.write(self.style.WARNING(
                # str(factor_type), not !r: Authenticator.Type is a
                # TextChoices (str subclass) whose repr is the noisy
                # "Authenticator.Type.EMAIL" rather than plain "email".
                f"{self.prefix}  skipped {user}: no adapter is registered "
                f"for '{factor_type}' on this install (MFA_FACTORS="
                f"{list(mfa_settings.MFA_FACTORS)!r}) -- the row would be "
                f"inert. Add '{factor_type}' to MFA_FACTORS and re-run."))
            return

        key = (user.pk, factor_type)
        if key in self._seen:
            self.counts["skipped_unsupported"] += 1
            self.stdout.write(self.style.WARNING(
                f"{self.prefix}  skipped {user}: a second enabled "
                f"{factor_type} source row was found for this user in the "
                f"same run. django_mfa holds one {factor_type} factor per "
                f"user, so only the first (ordered by pk) was considered "
                f"-- this one was left out rather than silently "
                f"overwriting it."))
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
        Authenticator.objects.create(user=user, type=factor_type, data=data)
        self.counts["imported"] += 1
        self.stdout.write(f"{self.prefix}  imported {factor_type} for {user}")

    def _report(self):
        # Unconditional, not per-row: see the module docstring's "acceptance
        # side" section. mfa2's own valid_window=30 verification call
        # (mfa/totp.py:24) accepts codes up to +/-15 minutes out of step;
        # django_mfa's fixed TOTP_VALID_WINDOW=1 accepts +/-30s. Nothing in
        # User_Keys records how skewed any given user's clock actually is,
        # so this can't be detected or skipped per row -- it's printed once
        # so an operator knows to expect some of these imported users to
        # need a clock fix or a re-enrolment, not a bug report.
        self.stdout.write(self.style.WARNING(
            "note: django-mfa2 accepted codes up to +/-15 minutes out of "
            "step (valid_window=30); django_mfa accepts +/-30s. Users with "
            "badly-skewed device clocks will need to correct the clock or "
            "re-enrol."))
        self.stdout.write(self.style.SUCCESS(
            f"{self.prefix}imported {self.counts['imported']}, "
            f"skipped {self.counts['skipped_existing']} already present, "
            f"skipped {self.counts['skipped_unsupported']} unrepresentable, "
            f"{self.counts['unknown_user']} rows with no matching user."))
