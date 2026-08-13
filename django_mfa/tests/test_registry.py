# django_mfa/tests/test_registry.py
from django.contrib.auth.models import User
from django.test import TestCase

from django_mfa.models import Authenticator
from django_mfa.registry import Adapter, Registry


class FakeAdapter(Adapter):
    type = "totp"
    verbose_name = "Fake TOTP"


class FakeMultiAdapter(Adapter):
    type = "webauthn"
    verbose_name = "Fake key"
    supports_multiple = True


class FakeRecoveryCodesAdapter(Adapter):
    type = "recovery_codes"
    verbose_name = "Fake recovery codes"
    counts_as_primary_factor = False
    # Mirrors the real adapter: generated at mfa:recovery_codes, never
    # enrolled. That the *production* adapter declares this is covered at the
    # view level (SecuritySettingsTests), against the real registry.
    supports_enroll = False


class RegistryTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.registry = Registry()
        self.registry.register(FakeAdapter())
        self.registry.register(FakeMultiAdapter())
        self.registry.register(FakeRecoveryCodesAdapter())

    def test_get_returns_adapter_by_type(self):
        self.assertIsInstance(self.registry.get("totp"), FakeAdapter)

    def test_get_unknown_type_raises(self):
        with self.assertRaises(KeyError):
            self.registry.get("nope")

    def test_duplicate_registration_raises(self):
        with self.assertRaises(ValueError):
            self.registry.register(FakeAdapter())

    def test_enabled_for_reflects_stored_authenticators(self):
        self.assertEqual(self.registry.enabled_for(self.user), [])
        Authenticator.objects.create(user=self.user, type="totp")
        self.assertEqual([a.type for a in self.registry.enabled_for(self.user)],
                         ["totp"])

    def test_available_for_excludes_singleton_already_enrolled(self):
        Authenticator.objects.create(user=self.user, type="totp")
        available = [a.type for a in self.registry.available_for(self.user)]
        self.assertNotIn("totp", available)
        self.assertIn("webauthn", available)

    def test_available_for_keeps_multiple_capable_factor(self):
        Authenticator.objects.create(user=self.user, type="webauthn")
        available = [a.type for a in self.registry.available_for(self.user)]
        self.assertIn("webauthn", available)

    def test_available_for_never_offers_recovery_codes(self):
        """Recovery codes are GENERATED (at mfa:recovery_codes), not enrolled:
        RecoveryCodesAdapter implements no begin_enroll, so Adapter's base
        raises NotImplementedError. available_for() feeds the security page's
        "add a method" list directly, so including recovery codes there put a
        link to a guaranteed 500 in front of every user without codes yet.
        A user with no recovery codes is exactly the case that regressed.
        """
        self.assertEqual(
            Authenticator.objects.filter(
                user=self.user, type="recovery_codes").count(), 0)
        available = [a.type for a in self.registry.available_for(self.user)]
        self.assertNotIn("recovery_codes", available)
        # ... and the factor is still verifiable once generated, which is the
        # distinction supports_enroll draws.
        Authenticator.objects.create(user=self.user, type="recovery_codes")
        self.assertIn("recovery_codes",
                      [a.type for a in self.registry.enabled_for(self.user)])

    def test_recovery_codes_only_are_enabled_but_not_primary(self):
        Authenticator.objects.create(user=self.user, type="recovery_codes")
        enabled = [a.type for a in self.registry.enabled_for(self.user)]
        primary = [a.type for a in self.registry.primary_enabled_for(self.user)]
        self.assertIn("recovery_codes", enabled)
        self.assertNotIn("recovery_codes", primary)

    def test_totp_is_enabled_and_primary(self):
        Authenticator.objects.create(user=self.user, type="totp")
        enabled = [a.type for a in self.registry.enabled_for(self.user)]
        primary = [a.type for a in self.registry.primary_enabled_for(self.user)]
        self.assertIn("totp", enabled)
        self.assertIn("totp", primary)

    def test_has_primary_factor_agrees_with_primary_enabled_for(self):
        """has_primary_factor() is the boolean counterpart to
        primary_enabled_for() -- Important 4. The two must never disagree,
        since counts_as_primary_factor on the adapters is the single source
        of truth both derive their type list from.
        """
        self.assertFalse(self.registry.has_primary_factor(self.user))
        self.assertEqual(self.registry.primary_enabled_for(self.user), [])

        # Recovery codes alone: enabled, but not primary -- must not flip
        # has_primary_factor() to True.
        Authenticator.objects.create(user=self.user, type="recovery_codes")
        self.assertFalse(self.registry.has_primary_factor(self.user))
        self.assertEqual(self.registry.primary_enabled_for(self.user), [])

        # A real primary factor: both must now agree it's True.
        Authenticator.objects.create(user=self.user, type="totp")
        self.assertTrue(self.registry.has_primary_factor(self.user))
        self.assertTrue(self.registry.primary_enabled_for(self.user))

    def test_has_primary_factor_runs_a_single_query(self):
        """Important 4: primary_enabled_for() runs one .exists() query per
        registered adapter (via enabled_for()), which on a fully-enrolled,
        verified user cost +3 queries on every authenticated request under
        MFA_REQUIRED=True. has_primary_factor() must cost exactly one query,
        regardless of how many adapters are registered -- this registry has
        three (totp, webauthn, recovery_codes).
        """
        Authenticator.objects.create(user=self.user, type="totp")
        with self.assertNumQueries(1):
            self.registry.has_primary_factor(self.user)

    def test_primary_enabled_for_costs_one_query_per_adapter_by_contrast(self):
        """Documents the exact cost has_primary_factor() replaces callers
        away from, for the callers that only need the boolean: three
        adapters registered here (totp, webauthn, recovery_codes) means
        three .exists() queries, one per adapter, every time
        primary_enabled_for() runs -- this is what MfaMiddleware,
        the enforcement decorator, and the notifications module used to pay
        on every relevant request before Important 4's fix.
        """
        Authenticator.objects.create(user=self.user, type="totp")
        with self.assertNumQueries(3):
            self.registry.primary_enabled_for(self.user)

    def test_unregister_removes_adapter(self):
        self.registry.unregister("totp")
        with self.assertRaises(KeyError):
            self.registry.get("totp")

    def test_unregister_unknown_type_raises(self):
        with self.assertRaises(KeyError):
            self.registry.unregister("nope")
