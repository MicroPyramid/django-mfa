"""Remove every factor from a user, so a locked-out user can re-enrol."""

from django.core.management.base import BaseCommand, CommandError

from django_mfa import events
from django_mfa.management.commands._support import (
    describe_authenticator,
    resolve_user,
)
from django_mfa.models import Authenticator
from django_mfa.registry import registry


class Command(BaseCommand):
    help = "Remove all of a user's MFA factors."

    def add_arguments(self, parser):
        parser.add_argument("user", help="username or pk")
        parser.add_argument("--yes", action="store_true",
                            help="skip the confirmation prompt")

    def handle(self, *args, **options):
        user = resolve_user(options["user"])
        authenticators = list(Authenticator.objects.filter(user=user))
        if not authenticators:
            self.stdout.write(f"{user} has no factors enrolled; nothing to do.")
            return

        for auth in authenticators:
            self.stdout.write(f"  - {describe_authenticator(auth)}")
        if not options["yes"]:
            answer = input(f"Remove {len(authenticators)} factor(s) from "
                           f"{user}? [y/N] ")
            if answer.strip().lower() not in ("y", "yes"):
                raise CommandError("Aborted.")

        for auth in authenticators:
            factor_type, name = auth.type, auth.name
            auth.delete()
            try:
                sender = type(registry.get(factor_type))
            except KeyError:
                # A row whose type is no longer registered -- MFA_FACTORS
                # narrowed, or registry.unregister(). Removing one is still a
                # supported action; there is simply no adapter class to name.
                # Same fallback as views/manage.py:manage_factors.
                sender = None
            # request=None: this event originates outside any request. Every
            # signal in events.py documents that as possible precisely so a
            # support-desk reset still reaches audit receivers, rather than
            # being the one factor removal that leaves no trace.
            events.factor_removed.send_robust(
                sender=sender, user=user, factor_type=factor_type,
                name=name, request=None)

        self.stdout.write(self.style.SUCCESS(
            f"Removed {len(authenticators)} factor(s) from {user}."))
