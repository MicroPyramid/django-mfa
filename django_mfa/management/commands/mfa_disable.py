"""Grant or revoke an MFA_REQUIRED exemption for one user."""

from datetime import datetime, timedelta

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from django_mfa import events
from django_mfa.management.commands._support import resolve_user
from django_mfa.models import MfaExemption


class Command(BaseCommand):
    help = "Exempt a user from MFA_REQUIRED (or revoke that exemption)."

    def add_arguments(self, parser):
        parser.add_argument("user", help="username or pk")
        parser.add_argument("--reason", help="why this user is exempt")
        parser.add_argument("--until", help="expiry date, YYYY-MM-DD")
        parser.add_argument("--revoke", action="store_true",
                            help="remove an existing exemption")

    def handle(self, *args, **options):
        user = resolve_user(options["user"])

        if options["revoke"]:
            deleted, _ = MfaExemption.objects.filter(user=user).delete()
            if not deleted:
                self.stdout.write(f"{user} has no exemption; nothing to do.")
                return
            events.mfa_exemption_changed.send_robust(
                sender=MfaExemption, user=user, reason=None,
                expires_at=None, revoked=True, request=None)
            self.stdout.write(self.style.SUCCESS(
                f"Revoked the MFA exemption for {user}."))
            return

        # Stripped, not just truthy: "--reason '   '" is a non-empty string
        # that would otherwise sail past a bare `if not reason`, defeating
        # the entire point of a mandatory reason.
        reason = (options["reason"] or "").strip()
        if not reason:
            # Mandatory on the write path: an unexplained permanent exemption
            # from a security requirement outlives everyone who remembers why
            # it exists.
            raise CommandError(
                "--reason is required when granting an exemption.")

        expires_at = None
        if options["until"]:
            try:
                parsed = datetime.strptime(options["until"], "%Y-%m-%d")
            except ValueError:
                raise CommandError(
                    f"--until must be YYYY-MM-DD, got {options['until']!r}."
                ) from None
            # End of the named date, not its start: an operator granting
            # "--until 2030-06-15" means the exemption covers the whole of
            # that day. Storing midnight instead (the original bug) makes
            # MfaExemption.objects.active_for() return None for the entire
            # named date -- a "one-day" exemption granting zero days of
            # coverage. Add a day and subtract a microsecond rather than
            # setting hour=23/minute=59/... by hand, so this can't silently
            # drop a field if datetime ever grows one.
            end_of_day = parsed + timedelta(days=1) - timedelta(microseconds=1)
            # Match the datetime's awareness to USE_TZ rather than always
            # calling make_aware(): test_runner.py never sets USE_TZ, so it
            # follows Django's default -- False on Django 4.2, this
            # project's floor and a leg of the CI matrix. Under
            # USE_TZ=False, storing a timezone-aware datetime raises
            # (SQLite rejects it outright), and MfaExemption.active_for()
            # compares expires_at__gt=timezone.now(), where timezone.now()
            # is naive -- mixing the two raises TypeError. Only make it
            # aware when the project is actually using aware datetimes.
            expires_at = (timezone.make_aware(end_of_day)
                          if settings.USE_TZ else end_of_day)
            if expires_at <= timezone.now():
                # A past --until must never be accepted: update_or_create()
                # below would otherwise overwrite a *live* exemption with an
                # already-expired one -- a functional revoke -- while the
                # command still reports a grant and emits
                # mfa_exemption_changed(revoked=False, expires_at=<past>).
                # The audit trail would then record the inverse of what
                # actually happened.
                raise CommandError(
                    f"--until {options['until']} is in the past.")

        MfaExemption.objects.update_or_create(
            user=user,
            defaults={"reason": reason, "expires_at": expires_at},
        )
        events.mfa_exemption_changed.send_robust(
            sender=MfaExemption, user=user, reason=reason,
            expires_at=expires_at, revoked=False, request=None)

        until = f" until {options['until']}" if expires_at else " permanently"
        self.stdout.write(self.style.WARNING(
            f"{user} is now exempt from MFA_REQUIRED{until}: {reason}"))
