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
        #
        # `or grace_state(...)` is load-bearing, not belt-and-braces:
        # mfa_required_for() returns False during the grace window, so
        # filtering on it alone would silently drop every user still inside
        # their window -- exactly the people a rollout needs to watch.
        # grace_state() returns non-None only for a user who WOULD be walled
        # but is not yet, so the pair is precisely "owes us a factor, now or
        # soon".
        #
        # grace_state() is computed AT MOST ONCE per user, here, and carried
        # through as (user, grace) pairs rather than recomputed in the CSV
        # and text loops below -- both mfa_required_for() and grace_state()
        # pay for the predicate and (on grace_state()'s side) an
        # has_active_exemption() query, and this command iterates the whole
        # user table. For a past-due user mfa_required_for() short-circuits
        # the `or`, so grace_state() is never called at all for them -- only
        # an in-grace user pays for it, and only once.
        outstanding = []
        for user in model.objects.all().iterator():
            if registry.has_primary_factor(user):
                continue
            if policy.mfa_required_for(user):
                outstanding.append((user, None))
                continue
            grace = policy.grace_state(user)
            if grace is not None:
                outstanding.append((user, grace))

        if options["format"] == "csv":
            writer = csv.writer(self.stdout)
            # grace_until is APPENDED, never inserted: a consumer indexing
            # by column position keeps working for the columns it knew about.
            writer.writerow(["pk", field, "grace_until"])
            for user, grace in outstanding:
                writer.writerow([
                    user.pk,
                    getattr(user, field),
                    grace.required_at.isoformat() if grace else "",
                ])
            return

        self.stdout.write(
            f"Required but unenrolled: {len(outstanding)}")
        for user, grace in outstanding:
            suffix = (f" -- in grace until {grace.required_at:%Y-%m-%d}"
                      if grace else "")
            self.stdout.write(f"  - {getattr(user, field)} (pk={user.pk}){suffix}")
