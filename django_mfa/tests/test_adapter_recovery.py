# django_mfa/tests/test_adapter_recovery.py
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from django.test import RequestFactory, TestCase

from django_mfa.adapters.recovery_codes import RecoveryCodesAdapter
from django_mfa.models import Authenticator
from django_mfa.registry import registry


class RecoveryCodesAdapterTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.adapter = RecoveryCodesAdapter()
        self.request = RequestFactory().get("/")
        self.request.user = self.user

    def test_generate_returns_ten_unique_codes(self):
        codes = self.adapter.generate(self.user)
        self.assertEqual(len(codes), 10)
        self.assertEqual(len(set(codes)), 10)

    def test_generated_codes_are_hashed_at_rest(self):
        codes = self.adapter.generate(self.user)
        auth = Authenticator.objects.get(user=self.user, type="recovery_codes")
        self.assertNotIn(codes[0], auth.data["codes"])

    def test_generate_returns_plaintext_while_storing_hashes(self):
        """generate() must hand back usable plaintext codes.

        If it returned the hashes instead, the user would be shown unusable
        strings on the "here are your recovery codes" screen — they'd never
        be able to type one back in successfully.
        """
        codes = self.adapter.generate(self.user)
        auth = Authenticator.objects.get(user=self.user, type="recovery_codes")
        for plaintext, stored in zip(codes, auth.data["codes"], strict=True):
            self.assertNotEqual(plaintext, stored)
            self.assertTrue(check_password(plaintext, stored))

    def test_regenerating_replaces_the_single_row(self):
        self.adapter.generate(self.user)
        self.adapter.generate(self.user)
        self.assertEqual(
            Authenticator.objects.filter(user=self.user,
                                         type="recovery_codes").count(), 1)

    def test_verify_accepts_a_code_once(self):
        codes = self.adapter.generate(self.user)
        self.assertTrue(
            self.adapter.complete_verify(self.request, self.user, {"code": codes[0]}))
        self.assertFalse(
            self.adapter.complete_verify(self.request, self.user, {"code": codes[0]}))

    def test_verify_rejects_unknown_code(self):
        self.adapter.generate(self.user)
        self.assertFalse(
            self.adapter.complete_verify(self.request, self.user, {"code": "nope"}))

    def test_verify_accepts_migrated_plaintext_code(self):
        """Codes carried over by migration 0005 are plaintext and must work."""
        Authenticator.objects.create(
            user=self.user, type="recovery_codes",
            data={"codes": ["aaaaaaaaaa"], "used": [], "migrated_plaintext": True})
        self.assertTrue(self.adapter.complete_verify(
            self.request, self.user, {"code": "aaaaaaaaaa"}))

    def test_verify_rejects_reused_migrated_plaintext_code(self):
        """A used plaintext code must be marked used, same as a hashed one.

        This is the scenario the brief calls out as the failure mode to
        design against: a user upgrading from the old version has plaintext
        codes on paper, and needs them to behave identically to freshly
        generated hashed codes -- including single-use semantics.
        """
        Authenticator.objects.create(
            user=self.user, type="recovery_codes",
            data={"codes": ["aaaaaaaaaa"], "used": [], "migrated_plaintext": True,
                  "migrated_from_legacy": True})
        self.assertTrue(self.adapter.complete_verify(
            self.request, self.user, {"code": "aaaaaaaaaa"}))
        self.assertFalse(self.adapter.complete_verify(
            self.request, self.user, {"code": "aaaaaaaaaa"}))

        auth = Authenticator.objects.get(user=self.user, type="recovery_codes")
        self.assertEqual(auth.data["used"], [0])
        # migrated_from_legacy must survive untouched -- the 0005 rollback
        # path keys off it to know which rows it created.
        self.assertTrue(auth.data["migrated_from_legacy"])

    def test_verify_with_no_authenticator_returns_false(self):
        self.assertFalse(
            self.adapter.complete_verify(self.request, self.user, {"code": "anything"}))

    def test_verify_with_empty_codes_list_returns_false(self):
        Authenticator.objects.create(
            user=self.user, type="recovery_codes", data={"codes": [], "used": []})
        self.assertFalse(
            self.adapter.complete_verify(self.request, self.user, {"code": "anything"}))

    def test_verify_with_missing_codes_key_returns_false(self):
        Authenticator.objects.create(
            user=self.user, type="recovery_codes", data={})
        self.assertFalse(
            self.adapter.complete_verify(self.request, self.user, {"code": "anything"}))

    def test_remaining_with_no_authenticator_is_zero(self):
        self.assertEqual(self.adapter.remaining(self.user), 0)

    def test_remaining_with_missing_codes_key_is_zero(self):
        Authenticator.objects.create(
            user=self.user, type="recovery_codes", data={})
        self.assertEqual(self.adapter.remaining(self.user), 0)

    def test_remaining_counts_unused(self):
        codes = self.adapter.generate(self.user)
        self.adapter.complete_verify(self.request, self.user, {"code": codes[0]})
        self.assertEqual(self.adapter.remaining(self.user), 9)

    def test_only_recovery_codes_enabled_but_not_primary(self):
        """A user holding ONLY recovery codes can verify but is not protected.

        Uses the real production registry singleton (populated by
        django_mfa.adapters at app-ready time) and the real
        RecoveryCodesAdapter, exercising counts_as_primary_factor end to end
        rather than the FakeRecoveryCodesAdapter used in test_registry.py.
        """
        self.adapter.generate(self.user)
        enabled = [a.type for a in registry.enabled_for(self.user)]
        primary = [a.type for a in registry.primary_enabled_for(self.user)]
        self.assertIn("recovery_codes", enabled)
        self.assertNotIn("recovery_codes", primary)
