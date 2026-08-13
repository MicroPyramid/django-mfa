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
