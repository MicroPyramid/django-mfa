from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase, override_settings

from django_mfa import ratelimit


class RateLimitTests(TestCase):
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
    def test_counters_are_per_factor(self):
        for _ in range(3):
            ratelimit.record_failure(self.user, "totp")
        self.assertTrue(ratelimit.check(self.user, "webauthn"))

    @override_settings(MFA_VERIFY_RATE_LIMIT="3/5m")
    def test_success_clears_the_counter(self):
        for _ in range(2):
            ratelimit.record_failure(self.user, "totp")
        ratelimit.clear(self.user, "totp")
        self.assertTrue(ratelimit.check(self.user, "totp"))

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

    @override_settings(MFA_VERIFY_RATE_LIMIT="3/5m")
    def test_counters_are_per_user(self):
        other = User.objects.create_user("b@example.com", password="pw")
        for _ in range(3):
            ratelimit.record_failure(self.user, "totp")
        self.assertFalse(ratelimit.check(self.user, "totp"))
        # A different user's budget is untouched by the first user's failures.
        self.assertTrue(ratelimit.check(other, "totp"))

    @override_settings(MFA_VERIFY_RATE_LIMIT="3/5m")
    def test_cache_eviction_fails_open(self):
        for _ in range(3):
            ratelimit.record_failure(self.user, "totp")
        self.assertFalse(ratelimit.check(self.user, "totp"))
        # Simulate the counter key being evicted from the cache mid-window
        # (e.g. locmem's max-entries eviction, or a cache flush/restart).
        cache.delete(ratelimit._key(self.user, "totp"))
        # With no record of prior failures, the throttle allows the request:
        # it fails OPEN, not closed.
        self.assertTrue(ratelimit.check(self.user, "totp"))


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


@override_settings(MFA_VERIFY_RATE_LIMIT="5/5m")
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
