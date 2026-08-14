from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import DatabaseError
from django.db.models import QuerySet
from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone

from django_mfa import ratelimit
from django_mfa.models import RateLimitCounter


class ParseTests(TestCase):
    """The spec grammar. Nothing here touches a backend."""

    def test_parses_hour_and_second_windows(self):
        self.assertEqual(ratelimit.parse("5/5m"), (5, 300))
        self.assertEqual(ratelimit.parse("10/1h"), (10, 3600))
        self.assertEqual(ratelimit.parse("2/30s"), (2, 30))

    def test_parse_rejects_malformed_specs(self):
        for spec in ("5", "5/", "5/5x", "", "abc"):
            with self.assertRaises(ValueError):
                ratelimit.parse(spec)

    def test_parse_rejects_zero_count(self):
        with self.assertRaises(ValueError) as ctx:
            ratelimit.parse("0/5m")
        self.assertIn("lock", str(ctx.exception).lower())

    def test_parse_rejects_zero_count_regardless_of_unit(self):
        with self.assertRaises(ValueError):
            ratelimit.parse("0/1h")

    def test_parse_rejects_zero_window(self):
        with self.assertRaises(ValueError):
            ratelimit.parse("5/0m")
        with self.assertRaises(ValueError):
            ratelimit.parse("5/0s")

    def test_parse_accepts_minimum_legitimate_values(self):
        self.assertEqual(ratelimit.parse("1/1s"), (1, 1))


class _BudgetContract:
    """What every backend must do, run once per backend below.

    Subclassed rather than parameterised so a backend that quietly stops
    counting fails a named test rather than being skipped -- the whole point
    of the database backend is that the cache one silently loses counters, and
    a contract only one of them is held to could not catch the reverse.
    """

    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user("a@example.com", password="pw")

    def test_allowed_by_default(self):
        self.assertTrue(ratelimit.check(self.user, "totp"))

    @override_settings(MFA_VERIFY_RATE_LIMIT="3/5m")
    def test_blocks_after_configured_attempts(self):
        for _ in range(3):
            ratelimit.record_failure(self.user, "totp")
        self.assertFalse(ratelimit.check(self.user, "totp"))

    @override_settings(MFA_VERIFY_RATE_LIMIT="3/5m")
    def test_the_last_allowed_attempt_is_allowed(self):
        for _ in range(2):
            ratelimit.record_failure(self.user, "totp")
        self.assertTrue(ratelimit.check(self.user, "totp"))

    @override_settings(MFA_VERIFY_RATE_LIMIT="3/5m")
    def test_counters_are_per_factor(self):
        for _ in range(3):
            ratelimit.record_failure(self.user, "totp")
        self.assertTrue(ratelimit.check(self.user, "webauthn"))

    @override_settings(MFA_VERIFY_RATE_LIMIT="3/5m")
    def test_counters_are_per_user(self):
        other = User.objects.create_user("b@example.com", password="pw")
        for _ in range(3):
            ratelimit.record_failure(self.user, "totp")
        self.assertFalse(ratelimit.check(self.user, "totp"))
        self.assertTrue(ratelimit.check(other, "totp"))

    @override_settings(MFA_VERIFY_RATE_LIMIT="3/5m")
    def test_success_clears_the_counter(self):
        for _ in range(2):
            ratelimit.record_failure(self.user, "totp")
        ratelimit.clear(self.user, "totp")
        self.assertTrue(ratelimit.check(self.user, "totp"))

    @override_settings(MFA_EMAIL_SEND_RATE_LIMIT="2/5m")
    def test_a_named_setting_supplies_the_limit(self):
        setting = "MFA_EMAIL_SEND_RATE_LIMIT"
        self.assertTrue(ratelimit.check(self.user, "email:send", setting=setting))
        ratelimit.record(self.user, "email:send", setting=setting)
        self.assertTrue(ratelimit.check(self.user, "email:send", setting=setting))
        ratelimit.record(self.user, "email:send", setting=setting)
        self.assertFalse(ratelimit.check(self.user, "email:send", setting=setting))

    @override_settings(MFA_EMAIL_SEND_RATE_LIMIT="1/5m",
                       MFA_VERIFY_RATE_LIMIT="5/5m")
    def test_scopes_do_not_share_a_counter(self):
        ratelimit.record(self.user, "email:send",
                         setting="MFA_EMAIL_SEND_RATE_LIMIT")
        self.assertFalse(ratelimit.check(self.user, "email:send",
                                         setting="MFA_EMAIL_SEND_RATE_LIMIT"))
        self.assertTrue(ratelimit.check(self.user, "email"))

    @override_settings(MFA_EMAIL_SEND_RATE_LIMIT="0/5m")
    def test_the_error_names_the_setting_that_is_wrong(self):
        with self.assertRaises(ValueError) as ctx:
            ratelimit.check(self.user, "email:send",
                            setting="MFA_EMAIL_SEND_RATE_LIMIT")
        self.assertIn("MFA_EMAIL_SEND_RATE_LIMIT", str(ctx.exception))
        self.assertNotIn("MFA_VERIFY_RATE_LIMIT", str(ctx.exception))

    def test_record_failure_is_still_the_verify_budget(self):
        """Existing callers (views/verify.py) are untouched by the refactor."""
        self.assertIs(ratelimit.record_failure, ratelimit.record)


@override_settings(MFA_RATE_LIMIT_BACKEND="cache")
class CacheBackendTests(_BudgetContract, TestCase):
    pass


@override_settings(MFA_RATE_LIMIT_BACKEND="database")
class DatabaseBackendTests(_BudgetContract, TestCase):
    pass


@override_settings(MFA_RATE_LIMIT_BACKEND="cache", MFA_VERIFY_RATE_LIMIT="3/5m")
class CacheEvictionTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user("a@example.com", password="pw")

    def test_cache_eviction_fails_open(self):
        for _ in range(3):
            ratelimit.record_failure(self.user, "totp")
        self.assertFalse(ratelimit.check(self.user, "totp"))
        # Simulate the counter key being evicted mid-window (locmem's
        # max-entries eviction, a flush, a restart).
        cache.delete(ratelimit._key(self.user, "totp"))
        # With no record of prior failures the throttle allows the request: it
        # fails OPEN. This is the hole the database backend closes, and it is
        # pinned here so that "the cache backend loses counters" stays a stated
        # property rather than a surprise.
        self.assertTrue(ratelimit.check(self.user, "totp"))


@override_settings(MFA_RATE_LIMIT_BACKEND="database",
                   MFA_VERIFY_RATE_LIMIT="3/5m")
class DatabaseDurabilityTests(TestCase):
    """The reason the database backend is the default."""

    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user("a@example.com", password="pw")

    def test_a_cache_flush_does_not_reset_the_budget(self):
        for _ in range(3):
            ratelimit.record_failure(self.user, "totp")
        self.assertFalse(ratelimit.check(self.user, "totp"))
        cache.clear()
        self.assertFalse(ratelimit.check(self.user, "totp"))

    def test_the_counter_is_a_row(self):
        ratelimit.record_failure(self.user, "totp")
        row = RateLimitCounter.objects.get(
            scope=ratelimit._key(self.user, "totp"))
        self.assertEqual(row.count, 1)
        self.assertGreater(row.expires_at, timezone.now())

    def test_repeated_failures_accumulate_on_one_row(self):
        for _ in range(3):
            ratelimit.record_failure(self.user, "totp")
        self.assertEqual(RateLimitCounter.objects.count(), 1)
        self.assertEqual(RateLimitCounter.objects.get().count, 3)

    def test_the_window_does_not_slide_forward_on_each_failure(self):
        """Fixed from the first failure, matching the cache backend exactly."""
        ratelimit.record_failure(self.user, "totp")
        first = RateLimitCounter.objects.get().expires_at
        ratelimit.record_failure(self.user, "totp")
        self.assertEqual(RateLimitCounter.objects.get().expires_at, first)

    def test_an_expired_counter_stops_binding(self):
        for _ in range(3):
            ratelimit.record_failure(self.user, "totp")
        self.assertFalse(ratelimit.check(self.user, "totp"))
        RateLimitCounter.objects.update(
            expires_at=timezone.now() - timedelta(seconds=1))
        self.assertTrue(ratelimit.check(self.user, "totp"))

    def test_an_expired_row_is_reused_with_a_fresh_window(self):
        ratelimit.record_failure(self.user, "totp")
        RateLimitCounter.objects.update(
            expires_at=timezone.now() - timedelta(seconds=1))
        ratelimit.record_failure(self.user, "totp")
        # Reset to 1, not incremented to 2 -- the old window's failures are
        # spent, and one row, not two.
        self.assertEqual(RateLimitCounter.objects.count(), 1)
        row = RateLimitCounter.objects.get()
        self.assertEqual(row.count, 1)
        self.assertGreater(row.expires_at, timezone.now())

    def test_losing_the_race_to_create_counts_on_top(self):
        """The IntegrityError branch: another request created the row first.

        The window it exists for is narrow -- between this caller's two
        UPDATEs finding nothing and its INSERT landing, someone else commits
        the same scope. Reproduced without threads by committing the winner's
        row up front and making the first two UPDATEs report zero rows
        matched, which is exactly what this caller would have seen.

        A thread would need TransactionTestCase and would be timing-dependent;
        this is the same code path, deterministically.
        """
        key = ratelimit._key(self.user, "totp")
        RateLimitCounter.objects.create(
            scope=key, count=1, expires_at=timezone.now() + timedelta(300))

        real_update, seen = QuerySet.update, {"n": 0}

        def blind_at_first(self, **kwargs):
            seen["n"] += 1
            if seen["n"] <= 2:
                return 0
            return real_update(self, **kwargs)

        with mock.patch.object(QuerySet, "update", blind_at_first):
            ratelimit.record_failure(self.user, "totp")

        # One row, not a duplicate, and the failure was not silently dropped:
        # the winner's 1 plus this caller's, counted on top.
        self.assertEqual(RateLimitCounter.objects.count(), 1)
        self.assertEqual(RateLimitCounter.objects.get().count, 2)

    def test_prune_deletes_only_expired_rows(self):
        ratelimit.record_failure(self.user, "totp")
        ratelimit.record_failure(self.user, "webauthn")
        RateLimitCounter.objects.filter(
            scope__endswith=":totp").update(
                expires_at=timezone.now() - timedelta(seconds=1))

        self.assertEqual(ratelimit.prune(), 1)
        self.assertEqual(
            [c.scope for c in RateLimitCounter.objects.all()],
            [ratelimit._key(self.user, "webauthn")])


class FailOpenTests(TestCase):
    """MFA_RATE_LIMIT_FAIL_OPEN governs an unreachable store, nothing else."""

    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user("a@example.com", password="pw")

    def _break_the_store(self):
        """Break it at the ORM, not at our own helper.

        Patching ratelimit._db_get would not work and would not fail loudly
        either: _BACKENDS binds the function objects at import, so the module
        attribute is no longer what gets called, and the test would pass by
        exercising a perfectly healthy store.
        """
        return mock.patch.object(
            RateLimitCounter.objects, "filter",
            side_effect=DatabaseError("no such table: django_mfa_ratelimitcounter"))

    @override_settings(MFA_RATE_LIMIT_BACKEND="database",
                       MFA_RATE_LIMIT_FAIL_OPEN=True)
    def test_an_unreachable_store_allows_by_default(self):
        with self._break_the_store(), self.assertLogs("django_mfa", "ERROR"):
            self.assertTrue(ratelimit.check(self.user, "totp"))

    @override_settings(MFA_RATE_LIMIT_BACKEND="database",
                       MFA_RATE_LIMIT_FAIL_OPEN=False)
    def test_an_unreachable_store_refuses_when_told_to(self):
        with self._break_the_store(), self.assertLogs("django_mfa", "ERROR"):
            self.assertFalse(ratelimit.check(self.user, "totp"))

    @override_settings(MFA_RATE_LIMIT_BACKEND="database")
    def test_an_outage_is_logged_rather_than_swallowed(self):
        """Failing open is invisible from the outside -- the site keeps
        working and the throttle silently stops. The log line is the only
        signal a host project's monitoring can act on."""
        with self._break_the_store(), self.assertLogs("django_mfa", "ERROR") as caught:
            ratelimit.check(self.user, "totp")
        self.assertIn("rate-limit store unavailable", caught.output[0])

    @override_settings(MFA_RATE_LIMIT_BACKEND="database",
                       MFA_RATE_LIMIT_FAIL_OPEN=False)
    def test_an_absent_counter_is_still_allowed_when_failing_closed(self):
        """The distinction the setting turns on.

        "No counter" means "nobody has failed yet" and must always be allowed;
        only the store being unable to answer is a failure. A limiter that
        read fail-closed as "deny on a miss" would deny every first attempt
        ever made -- i.e. every login.
        """
        self.assertTrue(ratelimit.check(self.user, "totp"))

    @override_settings(MFA_RATE_LIMIT_BACKEND="database")
    def test_a_broken_store_does_not_raise_out_of_record(self):
        """An outage must not turn a wrong code into a 500."""
        with self._break_the_store(), self.assertLogs("django_mfa", "ERROR"):
            ratelimit.record_failure(self.user, "totp")   # must not raise
            ratelimit.clear(self.user, "totp")            # nor this

    @override_settings(MFA_RATE_LIMIT_BACKEND="cache",
                       MFA_RATE_LIMIT_FAIL_OPEN=True)
    def test_a_cache_client_error_is_caught_too(self):
        """Cache clients raise their own hierarchies, with no Django base.

        redis.ConnectionError and pylibmc.Error share no ancestor with
        DatabaseError, which is why the cache backend's "unavailable" class is
        bare Exception rather than something narrower.
        """
        class RedisConnectionError(Exception):
            pass

        broken = mock.Mock()
        broken.get.side_effect = RedisConnectionError("connection refused")
        with mock.patch.object(ratelimit, "cache", broken), \
                self.assertLogs("django_mfa", "ERROR"):
            self.assertTrue(ratelimit.check(self.user, "totp"))

    @override_settings(MFA_RATE_LIMIT_BACKEND="cache",
                       MFA_RATE_LIMIT_FAIL_OPEN=False)
    def test_a_cache_outage_refuses_when_failing_closed(self):
        class RedisConnectionError(Exception):
            pass

        broken = mock.Mock()
        broken.get.side_effect = RedisConnectionError("connection refused")
        with mock.patch.object(ratelimit, "cache", broken), \
                self.assertLogs("django_mfa", "ERROR"):
            self.assertFalse(ratelimit.check(self.user, "totp"))

    @override_settings(MFA_RATE_LIMIT_BACKEND="nonsense")
    def test_an_unknown_backend_is_refused_loudly(self):
        with self.assertRaises(ValueError) as ctx:
            ratelimit.check(self.user, "totp")
        self.assertIn("MFA_RATE_LIMIT_BACKEND", str(ctx.exception))


class ClientIpTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_remote_addr_by_default(self):
        request = self.factory.get("/", REMOTE_ADDR="203.0.113.7")
        self.assertEqual(ratelimit.client_ip(request), "203.0.113.7")

    def test_x_forwarded_for_is_ignored(self):
        """A client-set header must not decide its own budget.

        Reading XFF by default breaks the limit in both directions at once:
        an attacker varying it is never throttled, and one setting it to a
        victim's address exhausts that victim's budget.
        """
        request = self.factory.get("/", REMOTE_ADDR="203.0.113.7",
                                   HTTP_X_FORWARDED_FOR="198.51.100.1")
        self.assertEqual(ratelimit.client_ip(request), "203.0.113.7")

    def test_no_address_at_all_is_none(self):
        request = self.factory.get("/")
        request.META.pop("REMOTE_ADDR", None)
        self.assertIsNone(ratelimit.client_ip(request))

    @override_settings(
        MFA_CLIENT_IP_RESOLVER="django_mfa.tests.test_ratelimit.last_forwarded")
    def test_a_resolver_replaces_it(self):
        request = self.factory.get("/", REMOTE_ADDR="10.0.0.1",
                                   HTTP_X_FORWARDED_FOR="198.51.100.1, 10.0.0.9")
        self.assertEqual(ratelimit.client_ip(request), "10.0.0.9")

    @override_settings(
        MFA_CLIENT_IP_RESOLVER="django_mfa.tests.test_ratelimit.no_address")
    def test_a_resolver_returning_none_disables_the_budget(self):
        request = self.factory.get("/", REMOTE_ADDR="203.0.113.7")
        self.assertIsNone(ratelimit.client_ip(request))
        self.assertTrue(ratelimit.check_client(request, "totp"))


def last_forwarded(request):
    """Test resolver: the hop our own proxy appended."""
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    return forwarded.rsplit(",", 1)[-1].strip() or None


def no_address(request):
    return None


@override_settings(MFA_VERIFY_IP_RATE_LIMIT="3/5m")
class IpBudgetTests(TestCase):
    def setUp(self):
        cache.clear()
        self.factory = RequestFactory()
        self.user = User.objects.create_user("a@example.com", password="pw")

    def _request(self, ip="203.0.113.7"):
        return self.factory.post("/", REMOTE_ADDR=ip)

    def test_blocks_after_configured_attempts(self):
        request = self._request()
        for _ in range(3):
            ratelimit.record_client(request, "totp")
        self.assertFalse(ratelimit.check_client(request, "totp"))

    def test_counters_are_per_address(self):
        for _ in range(3):
            ratelimit.record_client(self._request("203.0.113.7"), "totp")
        self.assertFalse(ratelimit.check_client(
            self._request("203.0.113.7"), "totp"))
        self.assertTrue(ratelimit.check_client(
            self._request("198.51.100.1"), "totp"))

    def test_one_address_spans_every_account(self):
        """The whole point: the per-user budget cannot see this attack.

        Ten accounts guessed once each leaves every per-user counter at 1 and
        none of them ever binding; the shared address counter is what stops it.
        """
        request = self._request()
        for i in range(3):
            user = User.objects.create_user(f"u{i}@example.com", password="pw")
            ratelimit.record_client(request, "totp")
            self.assertTrue(ratelimit.check(user, "totp"))
        self.assertFalse(ratelimit.check_client(request, "totp"))

    def test_the_ip_counter_shares_nothing_with_the_user_counter(self):
        request = self._request()
        for _ in range(3):
            ratelimit.record_client(request, "totp")
        self.assertTrue(ratelimit.check(self.user, "totp"))

    @override_settings(MFA_VERIFY_IP_RATE_LIMIT=None)
    def test_none_switches_the_budget_off(self):
        request = self._request()
        for _ in range(10):
            ratelimit.record_client(request, "totp")
        self.assertTrue(ratelimit.check_client(request, "totp"))
        self.assertEqual(RateLimitCounter.objects.count(), 0)

    def test_an_unknown_address_skips_the_budget(self):
        request = self.factory.post("/")
        request.META.pop("REMOTE_ADDR", None)
        for _ in range(10):
            ratelimit.record_client(request, "totp")
        self.assertTrue(ratelimit.check_client(request, "totp"))

    def test_there_is_no_way_to_clear_it(self):
        """Deliberate: see flows.attempt_verify and record_client's docstring.

        An attacker only needs one account they control to log into, so an
        IP counter cleared on success would be reset at will.
        """
        self.assertFalse(hasattr(ratelimit, "clear_client"))


class _InterleavingCache:
    """Wraps a real cache so a second attempt lands mid-way through the first.

    Deterministically reproduces what two simultaneous requests do to a
    counter, without threads: ``hook`` runs once, immediately after the first
    cache operation the wrapped caller performs. Hooking on "the first
    operation, whatever it is" rather than on ``get`` specifically is what
    makes this test discriminate between implementations -- a get-then-set
    loses the interleaved increment, an add-then-incr does not.
    """

    def __init__(self, real, hook):
        self._real = real
        self._hook = hook
        self._fired = False

    def __getattr__(self, name):
        attr = getattr(self._real, name)

        def wrapper(*args, **kwargs):
            try:
                return attr(*args, **kwargs)
            finally:
                # In a finally, so the interleaving still happens when the
                # wrapped operation raises -- cache.incr() raising ValueError
                # for a not-yet-seeded counter is a normal step of the very
                # code path under test, not a reason to skip the hook.
                if not self._fired:
                    self._fired = True
                    self._hook()

        return wrapper


@override_settings(MFA_RATE_LIMIT_BACKEND="cache", MFA_VERIFY_RATE_LIMIT="5/5m")
class RateLimitAtomicityTests(TestCase):
    """The counter must not lose increments under concurrency.

    check() and record_failure() are the only thing standing between an
    attacker and unlimited 6-digit TOTP guesses. Read-modify-write on the
    counter means parallel attempts overwrite each other's increments, so the
    limit stops binding for anyone willing to send requests concurrently.
    """

    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user("a@example.com", password="pw")

    def _count(self):
        return cache.get(ratelimit._key(self.user, "totp"), 0)

    def test_an_interleaved_failure_is_not_lost(self):
        def concurrent_attempt():
            ratelimit.record_failure(self.user, "totp")

        with mock.patch.object(
                ratelimit, "cache",
                _InterleavingCache(cache, concurrent_attempt)):
            ratelimit.record_failure(self.user, "totp")

        self.assertEqual(self._count(), 2)

    def test_the_limit_still_binds_when_attempts_interleave(self):
        def concurrent_attempts():
            for _ in range(5):
                ratelimit.record_failure(self.user, "totp")

        with mock.patch.object(
                ratelimit, "cache",
                _InterleavingCache(cache, concurrent_attempts)):
            ratelimit.record_failure(self.user, "totp")

        self.assertFalse(ratelimit.check(self.user, "totp"))

    def test_the_window_is_still_applied_to_a_freshly_seeded_counter(self):
        ratelimit.record_failure(self.user, "totp")
        ttl = cache.ttl(ratelimit._key(self.user, "totp")) if hasattr(
            cache, "ttl") else None
        self.assertEqual(self._count(), 1)
        if ttl is not None:
            self.assertGreater(ttl, 0)
