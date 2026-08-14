"""Print one user's enrolled factors. Read-only."""

from django.core.management.base import BaseCommand

from django_mfa import policy
from django_mfa.adapters.recovery_codes import RecoveryCodesAdapter
from django_mfa.management.commands._support import (
    describe_authenticator,
    format_date,
    resolve_user,
)
from django_mfa.models import Authenticator, MfaExemption
from django_mfa.registry import registry


class Command(BaseCommand):
    help = "Show a user's enrolled MFA factors."

    def add_arguments(self, parser):
        parser.add_argument("user", help="username or pk")

    def handle(self, *args, **options):
        user = resolve_user(options["user"])
        self.stdout.write(f"User: {user} (pk={user.pk})")

        authenticators = Authenticator.objects.filter(user=user).order_by(
            "type", "created_at")
        if authenticators:
            for auth in authenticators:
                self.stdout.write(f"  - {describe_authenticator(auth)}")
        else:
            self.stdout.write("  (no factors enrolled)")

        remaining = RecoveryCodesAdapter().remaining(user)
        self.stdout.write(f"Recovery codes remaining: {remaining}")
        self.stdout.write(
            f"Protected: {'yes' if registry.has_primary_factor(user) else 'no'}")

        # policy.mfa_required_for() is the single source of truth for "is
        # this user required to hold a factor" -- reimplementing its body
        # here (resolve() + predicate(user) + is_authenticated +
        # has_active_exemption()) would make this command a second,
        # independent definition of a security predicate, exactly the
        # pattern models.PRIMARY_FACTOR_TYPES showed is costly (it silently
        # diverged from the registry). A second query for the exemption row
        # itself below is fine -- this is a support command, not a hot path.
        required = policy.mfa_required_for(user)
        self.stdout.write(f"Required: {'yes' if required else 'no'}")

        grace = policy.grace_state(user)
        if grace is not None:
            self.stdout.write(
                f"In grace until {grace.required_at:%Y-%m-%d} "
                f"({grace.days_remaining} days)")

        exemption = MfaExemption.objects.active_for(user)

        if exemption is not None:
            until = (f" until {format_date(exemption.expires_at)}"
                     if exemption.expires_at else " (permanent)")
            self.stdout.write(f"Exempt: {exemption.reason}{until}")
