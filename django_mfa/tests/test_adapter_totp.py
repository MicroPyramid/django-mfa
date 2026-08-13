# django_mfa/tests/test_adapter_totp.py
import base64
import datetime
import random

from django.contrib.auth.models import User
from django.test import RequestFactory, TestCase

from django_mfa import totp as totp_mod
from django_mfa.adapters.totp import TOTPAdapter, generate_secret
from django_mfa.crypto import decrypt
from django_mfa.models import Authenticator


class TOTPAdapterTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.adapter = TOTPAdapter()
        self.factory = RequestFactory()

    def _request(self):
        request = self.factory.get("/")
        request.user = self.user
        request.session = {}
        return request

    def test_begin_enroll_returns_secret_and_qr_uri(self):
        ctx = self.adapter.begin_enroll(self._request())
        self.assertIn("secret_key", ctx)
        self.assertTrue(ctx["provisioning_uri"].startswith("otpauth://totp/"))

    def test_complete_enroll_rejects_wrong_code(self):
        request = self._request()
        ctx = self.adapter.begin_enroll(request)
        with self.assertRaises(ValueError):
            self.adapter.complete_enroll(
                request, {"secret_key": ctx["secret_key"], "code": "000000"})

    def test_complete_enroll_stores_encrypted_secret(self):
        request = self._request()
        ctx = self.adapter.begin_enroll(request)
        code = totp_mod.TOTP(ctx["secret_key"]).now()

        auth = self.adapter.complete_enroll(
            request, {"secret_key": ctx["secret_key"], "code": code})

        self.assertEqual(auth.type, Authenticator.Type.TOTP)
        self.assertEqual(decrypt(auth.data["secret"]), ctx["secret_key"])

    def test_complete_verify_accepts_current_code(self):
        secret = "JBSWY3DPEHPK3PXP"
        Authenticator.objects.create(user=self.user, type="totp",
                                     data={"secret": secret})
        code = totp_mod.TOTP(secret).now()
        self.assertTrue(self.adapter.complete_verify(
            self._request(), self.user, {"code": code}))

    def test_complete_verify_rejects_wrong_code(self):
        Authenticator.objects.create(user=self.user, type="totp",
                                     data={"secret": "JBSWY3DPEHPK3PXP"})
        self.assertFalse(self.adapter.complete_verify(
            self._request(), self.user, {"code": "000000"}))

    def test_complete_verify_accepts_previous_window_code(self):
        secret = "JBSWY3DPEHPK3PXP"
        Authenticator.objects.create(user=self.user, type="totp",
                                     data={"secret": secret})
        code = totp_mod.TOTP(secret).at(datetime.datetime.now(), -1)
        self.assertTrue(self.adapter.complete_verify(
            self._request(), self.user, {"code": code}))

    def test_complete_verify_accepts_next_window_code(self):
        secret = "JBSWY3DPEHPK3PXP"
        Authenticator.objects.create(user=self.user, type="totp",
                                     data={"secret": secret})
        code = totp_mod.TOTP(secret).at(datetime.datetime.now(), 1)
        self.assertTrue(self.adapter.complete_verify(
            self._request(), self.user, {"code": code}))

    def test_complete_verify_rejects_code_two_windows_out(self):
        secret = "JBSWY3DPEHPK3PXP"
        Authenticator.objects.create(user=self.user, type="totp",
                                     data={"secret": secret})
        totp = totp_mod.TOTP(secret)
        now = datetime.datetime.now()
        self.assertFalse(self.adapter.complete_verify(
            self._request(), self.user, {"code": totp.at(now, -2)}))
        self.assertFalse(self.adapter.complete_verify(
            self._request(), self.user, {"code": totp.at(now, 2)}))

    def test_complete_enroll_accepts_previous_window_code(self):
        request = self._request()
        ctx = self.adapter.begin_enroll(request)
        code = totp_mod.TOTP(ctx["secret_key"]).at(datetime.datetime.now(), -1)

        auth = self.adapter.complete_enroll(
            request, {"secret_key": ctx["secret_key"], "code": code})

        self.assertEqual(auth.type, Authenticator.Type.TOTP)
        self.assertEqual(decrypt(auth.data["secret"]), ctx["secret_key"])


class TOTPSecretEntropyTests(TestCase):
    """generate_secret() must draw from a CSPRNG, not the `random` module.

    random.getrandbits() is the Mersenne Twister: its state is recoverable
    from 624 observed outputs, after which every subsequently issued TOTP
    secret is predictable. A shared secret that lives for the life of an
    enrollment must not come from a reproducible generator.
    """

    def test_seeding_the_random_module_does_not_reproduce_a_secret(self):
        random.seed(1234)
        first = generate_secret()
        random.seed(1234)
        second = generate_secret()
        self.assertNotEqual(first, second)

    def test_restoring_the_random_module_state_does_not_predict_a_secret(self):
        state = random.getstate()
        first = generate_secret()
        random.setstate(state)
        second = generate_secret()
        self.assertNotEqual(first, second)

    def test_secret_carries_at_least_160_bits(self):
        # RFC 4226 R6: the shared secret SHOULD be at least 160 bits.
        raw = base64.b32decode(generate_secret())
        self.assertGreaterEqual(len(raw) * 8, 160)

    def test_secret_needs_no_base32_padding(self):
        # OTP.byte_secret() re-pads in place and provisioning_uri() embeds the
        # secret verbatim, so a padded secret would put '=' inside the
        # otpauth:// query string.
        self.assertNotIn("=", generate_secret())


class TOTPReplayTests(TestCase):
    """RFC 6238 section 5.2: the verifier MUST NOT accept a second use of the
    same OTP within the same time step. With TOTP_VALID_WINDOW = 1 an accepted
    code would otherwise stay replayable for roughly 90 seconds.
    """

    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.adapter = TOTPAdapter()
        self.secret = "JBSWY3DPEHPK3PXP"
        Authenticator.objects.create(user=self.user, type="totp",
                                     data={"secret": self.secret})

    def _verify(self, code):
        return self.adapter.complete_verify(None, self.user, {"code": code})

    def test_the_same_code_is_rejected_on_second_use(self):
        code = totp_mod.TOTP(self.secret).now()
        self.assertTrue(self._verify(code))
        self.assertFalse(self._verify(code))

    def test_an_earlier_window_code_is_rejected_after_a_later_one_is_used(self):
        totp = totp_mod.TOTP(self.secret)
        now = datetime.datetime.now()
        self.assertTrue(self._verify(totp.at(now, 1)))
        self.assertFalse(self._verify(totp.at(now, 0)))
        self.assertFalse(self._verify(totp.at(now, -1)))

    def test_a_later_window_code_still_verifies_after_an_earlier_one(self):
        totp = totp_mod.TOTP(self.secret)
        now = datetime.datetime.now()
        self.assertTrue(self._verify(totp.at(now, -1)))
        self.assertTrue(self._verify(totp.at(now, 1)))
