from django.test import TestCase, override_settings

from django_mfa.crypto import decrypt, encrypt


class CryptoTests(TestCase):
    def test_noop_without_keys(self):
        self.assertEqual(encrypt("JBSWY3DPEHPK3PXP"), "JBSWY3DPEHPK3PXP")
        self.assertEqual(decrypt("JBSWY3DPEHPK3PXP"), "JBSWY3DPEHPK3PXP")

    @override_settings(MFA_SECRET_ENCRYPTION_KEYS=["k1-abcdefghijklmnop"])
    def test_round_trip_with_key(self):
        token = encrypt("JBSWY3DPEHPK3PXP")
        self.assertNotEqual(token, "JBSWY3DPEHPK3PXP")
        self.assertEqual(decrypt(token), "JBSWY3DPEHPK3PXP")

    @override_settings(MFA_SECRET_ENCRYPTION_KEYS=["k2-newkey", "k1-abcdefghijklmnop"])
    def test_decrypts_with_rotated_older_key(self):
        with override_settings(MFA_SECRET_ENCRYPTION_KEYS=["k1-abcdefghijklmnop"]):
            token = encrypt("JBSWY3DPEHPK3PXP")
        self.assertEqual(decrypt(token), "JBSWY3DPEHPK3PXP")

    @override_settings(MFA_SECRET_ENCRYPTION_KEYS=["k1-abcdefghijklmnop"])
    def test_plaintext_still_readable_after_enabling_encryption(self):
        """Hosts enabling encryption must not lock out already-stored secrets."""
        self.assertEqual(decrypt("JBSWY3DPEHPK3PXP"), "JBSWY3DPEHPK3PXP")
