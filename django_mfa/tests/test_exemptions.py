from datetime import datetime, time, timedelta
from io import StringIO

from django.contrib.auth.models import User
from django.core.management import CommandError, call_command
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from django.views.generic import View

from django_mfa import events, policy
from django_mfa.decorators import MfaRequiredMixin, mfa_required
from django_mfa.models import MfaExemption


class MfaExemptionModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")

    def test_permanent_exemption_is_active(self):
        e = MfaExemption.objects.create(user=self.user, reason="service account")
        self.assertTrue(e.is_active())

    def test_future_expiry_is_active(self):
        e = MfaExemption.objects.create(
            user=self.user, reason="onboarding",
            expires_at=timezone.now() + timedelta(days=1))
        self.assertTrue(e.is_active())

    def test_past_expiry_is_not_active(self):
        e = MfaExemption.objects.create(
            user=self.user, reason="onboarding",
            expires_at=timezone.now() - timedelta(seconds=1))
        self.assertFalse(e.is_active())

    def test_active_for_returns_none_when_expired(self):
        MfaExemption.objects.create(
            user=self.user, reason="x",
            expires_at=timezone.now() - timedelta(seconds=1))
        self.assertIsNone(MfaExemption.objects.active_for(self.user))

    def test_one_exemption_per_user(self):
        # OneToOneField -> a unique constraint at the database level. The
        # atomic() block is required: an IntegrityError inside a TestCase
        # poisons the surrounding transaction otherwise, and every later
        # assertion in this test method fails with TransactionManagementError.
        from django.db import IntegrityError, transaction

        MfaExemption.objects.create(user=self.user, reason="a")
        with self.assertRaises(IntegrityError), transaction.atomic():
            MfaExemption.objects.create(user=self.user, reason="b")


class MfaExemptionStrTests(TestCase):
    """str(exemption) is not just a display nicety: MfaExemptionAdmin's
    docstring names delete as the documented revoke path, and Django's admin
    calls str(obj) to render the confirm-delete page and again to write
    LogEntry.object_repr on deletion -- both real code paths that must not
    500. conf.py/checks.py never require USE_TZ=True, and this project's
    floor (Django 4.2, part of the CI matrix) defaults it to False, under
    which every stored/`timezone.now()` datetime is naive -- so this must
    hold under both settings, not just whichever one the dev machine's
    Django version happens to default to.
    """

    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")

    @override_settings(USE_TZ=True)
    def test_str_with_expiry_under_use_tz_true(self):
        e = MfaExemption.objects.create(
            user=self.user, reason="x",
            expires_at=timezone.now() + timedelta(days=1))
        self.assertIn("until", str(e))

    @override_settings(USE_TZ=False)
    def test_str_with_expiry_under_use_tz_false(self):
        e = MfaExemption.objects.create(
            user=self.user, reason="x",
            expires_at=timezone.now() + timedelta(days=1))
        self.assertIn("until", str(e))

    def test_str_without_expiry_has_no_until_suffix(self):
        e = MfaExemption.objects.create(user=self.user, reason="x")
        self.assertNotIn("until", str(e))


@override_settings(MFA_REQUIRED=True)
class PolicyExemptionTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")

    def test_required_without_exemption(self):
        self.assertTrue(policy.mfa_required_for(self.user))

    def test_active_exemption_suppresses_the_requirement(self):
        MfaExemption.objects.create(user=self.user, reason="service account")
        self.assertFalse(policy.mfa_required_for(self.user))

    def test_expired_exemption_does_not_suppress(self):
        MfaExemption.objects.create(
            user=self.user, reason="x",
            expires_at=timezone.now() - timedelta(seconds=1))
        self.assertTrue(policy.mfa_required_for(self.user))

    @override_settings(MFA_REQUIRED=False)
    def test_no_query_when_nobody_is_required(self):
        # The exemption lookup runs only after the predicate says yes, so the
        # default install pays nothing for this feature.
        MfaExemption.objects.create(user=self.user, reason="x")
        with self.assertNumQueries(0):
            self.assertFalse(policy.mfa_required_for(self.user))


@override_settings(MFA_REQUIRED=True)
class MiddlewareExemptionTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.client.force_login(self.user)

    def test_unenrolled_required_user_is_walled(self):
        response = self.client.get(reverse("mfa:manage"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("mfa:security_settings"), response["Location"])

    def test_exempt_user_is_not_walled(self):
        MfaExemption.objects.create(user=self.user, reason="service account")
        response = self.client.get(reverse("mfa:manage"))
        # 405: reached the POST-only view rather than being redirected away.
        self.assertEqual(response.status_code, 405)


@override_settings(MFA_REQUIRED=True)
class ExemptionDoesNotOpenDecoratedViewsTests(TestCase):
    """An MfaExemption suppresses MFA_REQUIRED only. It must never let a
    factorless, exempt user through a view behind @mfa_required or
    MfaRequiredMixin -- MFA_REQUIRED picks *users*, the decorator picks
    *views*, and decorators.py's own module docstring says the two are not
    interchangeable. decorators._enforce() does not import django_mfa.policy
    at all today, so this passes for a structural reason rather than by
    coincidence -- these tests exist to keep it that way: the obvious future
    "simplification" of having _enforce()'s factorless rung also consult
    policy.mfa_required_for(), "for consistency with the middleware", would
    silently let every exempt-but-factorless user reach every decorated
    view. Called by invoking the decorator/mixin directly rather than through
    self.client, so MfaMiddleware (which is not involved in this question)
    cannot mask a regression here by redirecting first.
    """

    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        MfaExemption.objects.create(user=self.user, reason="service account")

    def _request(self):
        request = RequestFactory().get("/billing/")
        request.user = self.user
        request.session = self.client.session
        return request

    def test_decorator_still_blocks_an_exempt_user_with_no_factor(self):
        view = mfa_required(lambda request: HttpResponse("ok"))
        response = view(self._request())
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("mfa:security_settings"), response["Location"])

    def test_mixin_still_blocks_an_exempt_user_with_no_factor(self):
        class ProtectedView(MfaRequiredMixin, View):
            def get(self, request):
                return HttpResponse("ok")

        response = ProtectedView.as_view()(self._request())
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("mfa:security_settings"), response["Location"])


class MfaDisableCommandTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("alice", password="pw")

    def _run(self, *args):
        out = StringIO()
        call_command("mfa_disable", *args, stdout=out)
        return out.getvalue()

    def test_creates_an_exemption(self):
        self._run("alice", "--reason", "service account")
        exemption = MfaExemption.objects.get(user=self.user)
        self.assertEqual(exemption.reason, "service account")
        self.assertIsNone(exemption.expires_at)

    def test_reason_is_mandatory(self):
        with self.assertRaises(CommandError):
            self._run("alice")

    def test_reason_of_only_whitespace_is_rejected(self):
        # Truthiness alone lets "   " through -- it's a non-empty string --
        # which defeats the entire point of a mandatory reason. Must be
        # stripped before the emptiness check.
        with self.assertRaises(CommandError):
            self._run("alice", "--reason", "   ")

    def test_until_sets_an_expiry(self):
        # Derived, not hardcoded: a literal date only stays in the future
        # until it doesn't, at which point the past-date guard below turns
        # this test into a CommandError failure with nothing to do with the
        # code under test. +365 days is always in the future regardless of
        # when this suite runs.
        future_date = (datetime.now() + timedelta(days=365)).date()
        self._run("alice", "--reason", "onboarding", "--until",
                  future_date.isoformat())
        exemption = MfaExemption.objects.get(user=self.user)
        expires = exemption.expires_at
        if timezone.is_aware(expires):
            # Storage is always UTC; the exemption's expiry is computed as
            # the last instant of the named date in the *local* (settings.
            # TIME_ZONE) calendar, which -- for any zone behind UTC, e.g.
            # this suite's ambient 'America/Chicago' -- lands on the next
            # calendar day once read back as a raw UTC value. localtime()
            # recovers the date an operator who typed --until actually
            # meant, the same conversion MfaExemption.__str__ and
            # format_date() already apply for display.
            expires = timezone.localtime(expires)
        self.assertEqual(expires.date().isoformat(), future_date.isoformat())

    def test_bad_until_errors(self):
        with self.assertRaises(CommandError):
            self._run("alice", "--reason", "x", "--until", "not-a-date")

    @override_settings(USE_TZ=False)
    def test_until_keeps_the_exemption_active_through_the_whole_named_date(self):
        # MUST FIX 1: a midnight-of-the-named-date expiry (the pre-fix
        # behaviour) makes MfaExemption.objects.active_for() return None for
        # the entire named date -- a "one-day" exemption that grants zero
        # days of coverage. "--until <date>" must keep the exemption in
        # force through the *end* of that date, not release it at its start.
        # USE_TZ=False sidesteps the local/UTC calendar-date shift that
        # aware storage introduces (see test_until_sets_an_expiry above),
        # keeping this test's arithmetic a direct, unambiguous check of the
        # stored instant.
        #
        # Derived, not hardcoded: see test_until_sets_an_expiry for why a
        # literal date is a time bomb here. datetime.now(), not
        # timezone.localdate(), because USE_TZ=False makes timezone.now()
        # naive and localdate()/localtime() both raise on a naive value.
        future_date = (datetime.now() + timedelta(days=365)).date()
        self._run("alice", "--reason", "onboarding", "--until",
                  future_date.isoformat())
        exemption = MfaExemption.objects.get(user=self.user)
        self.assertGreater(
            exemption.expires_at,
            datetime.combine(future_date, time(23, 0, 0)))
        self.assertLess(
            exemption.expires_at,
            datetime.combine(future_date + timedelta(days=1), time(0, 0, 0)))

    def test_past_until_is_rejected(self):
        # MUST FIX 1: a past --until must never be accepted, whether or not
        # an exemption already exists for the user -- see the next test for
        # why silently accepting one is actively dangerous, not just
        # pointless.
        with self.assertRaises(CommandError):
            self._run("alice", "--reason", "x", "--until", "2020-01-01")

    def test_past_until_does_not_overwrite_an_active_exemption(self):
        # MUST FIX 1: update_or_create() would otherwise overwrite a live
        # exemption with an already-expired one -- a functional revoke --
        # while the command still reports a grant and emits
        # mfa_exemption_changed(revoked=False, expires_at=<past>). The audit
        # trail would then record the inverse of what happened. Rejecting
        # the past date outright (previous test) prevents this outcome by
        # never reaching update_or_create() at all.
        self._run("alice", "--reason", "first", "--until", "2030-01-01")
        with self.assertRaises(CommandError):
            self._run("alice", "--reason", "revoke-attempt",
                      "--until", "2020-01-01")
        exemption = MfaExemption.objects.get(user=self.user)
        self.assertEqual(exemption.reason, "first")
        self.assertTrue(exemption.is_active())

    def test_revoke_removes_it(self):
        MfaExemption.objects.create(user=self.user, reason="x")
        self._run("--revoke", "alice")
        self.assertFalse(MfaExemption.objects.filter(user=self.user).exists())

    def test_revoke_without_one_is_not_an_error(self):
        self.assertIn("no exemption", self._run("--revoke", "alice").lower())

    def test_rerunning_replaces_the_reason(self):
        self._run("alice", "--reason", "first")
        self._run("alice", "--reason", "second")
        self.assertEqual(MfaExemption.objects.get(user=self.user).reason,
                         "second")

    def test_emits_the_signal_on_create_and_revoke(self):
        seen = []

        def receiver(sender, **kwargs):
            seen.append(kwargs)

        events.mfa_exemption_changed.connect(receiver)
        try:
            self._run("alice", "--reason", "service account")
            self._run("--revoke", "alice")
        finally:
            events.mfa_exemption_changed.disconnect(receiver)

        self.assertEqual(len(seen), 2)
        self.assertFalse(seen[0]["revoked"])
        self.assertEqual(seen[0]["reason"], "service account")
        self.assertIsNone(seen[0]["request"])
        self.assertTrue(seen[1]["revoked"])

    def test_signal_is_reexported_from_signals(self):
        from django_mfa.signals import mfa_exemption_changed
        self.assertIs(mfa_exemption_changed, events.mfa_exemption_changed)


class MfaDisableUntilUseTzTests(TestCase):
    """`--until` must produce a datetime whose awareness matches USE_TZ.

    The brief this command was written from has `handle()` call
    `timezone.make_aware(parsed)` unconditionally. test_runner.py never sets
    USE_TZ, so it follows Django's default -- False on Django 4.2, this
    project's floor and a leg of the CI matrix. Under USE_TZ=False, saving a
    timezone-aware datetime raises (SQLite rejects it outright), and
    MfaExemption.objects.active_for() compares expires_at__gt=timezone.now(),
    where timezone.now() is naive -- mixing the two raises TypeError. Same
    class of bug as Task 5's timezone.localtime() crash and Task 6's UTC
    date display; this locks in the fix for the third occurrence.

    Both tests grant a dated exemption through the real command and read it
    back through the real manager method, under the setting each is named
    for, so a regression back to the unguarded call is caught by an outright
    exception under USE_TZ=False (SQLite backend does not support
    timezone-aware datetimes when USE_TZ is False) rather than merely a
    wrong value.
    """

    def setUp(self):
        self.user = User.objects.create_user("alice", password="pw")

    def _run(self, *args):
        out = StringIO()
        call_command("mfa_disable", *args, stdout=out)
        return out.getvalue()

    @override_settings(USE_TZ=True)
    def test_until_round_trips_under_use_tz_true(self):
        # Derived, not hardcoded: see test_until_sets_an_expiry (above, in
        # MfaDisableCommandTests) for why a literal date is a time bomb
        # against the past-date guard. datetime.now(), not
        # timezone.localdate(): this method's own override_settings makes
        # USE_TZ=True locally, but the helper must work the same way as its
        # USE_TZ=False sibling below, so both use the same plain stdlib call.
        future_date = (datetime.now() + timedelta(days=365)).date()
        self._run("alice", "--reason", "onboarding", "--until",
                  future_date.isoformat())
        exemption = MfaExemption.objects.active_for(self.user)
        self.assertIsNotNone(exemption)
        self.assertTrue(timezone.is_aware(exemption.expires_at))
        # localtime(), not a bare .date() on the stored (UTC) value: the
        # expiry is the last instant of the named date in the *local*
        # (settings.TIME_ZONE) calendar, which -- behind UTC, as this
        # suite's ambient 'America/Chicago' is -- reads back as the next
        # calendar day in raw UTC. Same conversion
        # MfaExemption.__str__/format_date() already apply so an operator
        # sees the date they typed.
        self.assertEqual(
            timezone.localtime(exemption.expires_at).date().isoformat(),
            future_date.isoformat())

    @override_settings(USE_TZ=False)
    def test_until_round_trips_under_use_tz_false(self):
        # datetime.now(), not timezone.localdate(): USE_TZ=False makes
        # timezone.now() naive, and localdate()/localtime() both raise on a
        # naive value.
        future_date = (datetime.now() + timedelta(days=365)).date()
        self._run("alice", "--reason", "onboarding", "--until",
                  future_date.isoformat())
        exemption = MfaExemption.objects.active_for(self.user)
        self.assertIsNotNone(exemption)
        self.assertFalse(timezone.is_aware(exemption.expires_at))
        self.assertEqual(exemption.expires_at.date().isoformat(),
                         future_date.isoformat())
