# django_mfa/tests/test_adapter_totp.py
import datetime

from django.contrib.auth.models import User
from django.test import RequestFactory, TestCase

from django_mfa import totp as totp_mod
from django_mfa.adapters.totp import TOTPAdapter
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
