"""Delete expired rate-limit counters.

The database rate-limit backend (``MFA_RATE_LIMIT_BACKEND = "database"``, the
default) has no equivalent of a cache TTL: a counter stops *counting* the
moment ``expires_at`` passes, but the row stays. Nothing reads an expired row
-- every query filters on ``expires_at`` -- so leaving them is a disk and
privacy question rather than a correctness one, which is exactly why it needs
a scheduled command instead of happening inside a request.

Run it on the same schedule as ``django-admin clearsessions``, and for the
same reason.
"""

from django.core.management.base import BaseCommand

from django_mfa import ratelimit
from django_mfa.conf import settings as mfa_settings


class Command(BaseCommand):
    help = "Delete expired django-mfa rate-limit counters."

    def add_arguments(self, parser):
        parser.add_argument(
            "--quiet", action="store_true",
            help="print nothing on success (for cron)")

    def handle(self, *args, **options):
        deleted = ratelimit.prune()
        if options["quiet"]:
            return
        self.stdout.write(f"Deleted {deleted} expired rate-limit counter(s).")
        if mfa_settings.MFA_RATE_LIMIT_BACKEND != "database":
            # Not an error -- an operator may be mid-switch, or running this
            # from a shared cron entry across several deployments -- but
            # silently deleting nothing forever looks like the command is
            # broken rather than inapplicable.
            self.stdout.write(self.style.WARNING(
                "MFA_RATE_LIMIT_BACKEND is "
                f"{mfa_settings.MFA_RATE_LIMIT_BACKEND!r}, so counters live in "
                "the cache and expire themselves. This command only prunes the "
                "database backend's rows."))
