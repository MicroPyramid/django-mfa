"""Rollout reporting: who is covered, and who still owes you a factor."""

import csv

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db.models import Count

from django_mfa import policy
from django_mfa.models import Authenticator
from django_mfa.registry import registry


class Command(BaseCommand):
    help = "Report MFA coverage, and users MFA_REQUIRED applies to who have none."

    def add_arguments(self, parser):
        parser.add_argument("--required-only", action="store_true",
                            help="skip the per-type counts")
        parser.add_argument("--format", choices=["text", "csv"], default="text")

    def handle(self, *args, **options):
        model = get_user_model()
        field = model.USERNAME_FIELD

        # --format csv means machine-readable output: a consumer piping this
        # into a file or a parser must see the header row first and nothing
        # else. Gate the prose counts block on the format too, not just
        # --required-only, or `mfa_report --format csv` (no --required-only)
        # prints two lines of prose ahead of the CSV header.
        if not options["required_only"] and options["format"] == "text":
            counts = (Authenticator.objects.values("type")
                      .annotate(n=Count("id")).order_by("type"))
            self.stdout.write("Enrolled factors by type:")
            for row in counts:
                self.stdout.write(f"  {row['type']}: {row['n']}")
            if not counts:
                self.stdout.write("  (none)")

        # mfa_required_for() resolves a host-supplied predicate, so this
        # cannot be pushed into the query -- MFA_REQUIRED may be an arbitrary
        # callable. has_primary_factor() first: it is the cheaper of the two
        # and excludes most users before the predicate (and its exemption
        # lookup) runs at all.
        outstanding = [
            user for user in model.objects.all().iterator()
            if not registry.has_primary_factor(user)
            and policy.mfa_required_for(user)
        ]

        if options["format"] == "csv":
            writer = csv.writer(self.stdout)
            writer.writerow(["pk", field])
            for user in outstanding:
                writer.writerow([user.pk, getattr(user, field)])
            return

        self.stdout.write(
            f"Required but unenrolled: {len(outstanding)}")
        for user in outstanding:
            self.stdout.write(f"  - {getattr(user, field)} (pk={user.pk})")
