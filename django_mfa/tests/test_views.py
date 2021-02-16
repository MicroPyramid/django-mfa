from django.contrib.auth.models import User

try:
    from django.core.urlresolvers import reverse
except Exception:
    from django.urls import reverse
from django.test import Client, TestCase
from django_mfa.models import *
from django.conf import settings
from django.contrib import auth
from django_mfa.apps import DjangoMfaAppConfig
from django_mfa import totp
import binascii


class Views_test_auth_factor(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="djangomfa@mp.com", email="djangomfa@mp.com", password="djangomfa"
        )
        UserOTP.objects.create(otp_type="TOTP", user=self.user, secret_key="secretke")
        # Note : secret_key length should be divisible by 8
        self.session = self.client.session
        UserRecoveryCodes.objects.create(
            user=UserOTP.objects.get(user=self.user), secret_code="ABcDg"
        )
        UserRecoveryCodes.objects.create(
            user=UserOTP.objects.get(user=self.user), secret_code="abcdefg"
        )
        session = self.client.session
        session["verfied_otp"] = True
        session.save()
        self.client.login(username="djangomfa@mp.com", password="djangomfa")

    def test_middleware_with_Securitysettings_view(self):
        session = self.client.session
        session["verfied_otp"] = False
        session.save()
        response = self.client.get(reverse("mfa:security_settings"))
        url = reverse("mfa:verify_otp") + "?next=" + reverse("mfa:security_settings")
        self.assertEquals(response.url, url)

    def test_verify_rmb_cookie_with_Securitysettings_view(self):
        settings.MFA_REMEMBER_MY_BROWSER = False
        response = self.client.get(reverse("mfa:security_settings"))
        self.assertEquals(response.status_code, 200)
        settings.MFA_REMEMBER_MY_BROWSER = True
        settings.MFA_REMEMBER_DAYS = 2
        response = self.client.get(reverse("mfa:security_settings"))
        self.assertEquals(response.status_code, 200)

    def test_security_settings_view(self):
        response = self.client.get(reverse("mfa:security_settings"))
        self.assertTemplateUsed(response, "django_mfa/security.html")

    def test_configure_mfa_view(self):
        response = self.client.get(reverse("mfa:configure_mfa"))
        self.assertTemplateUsed(response, "django_mfa/configure.html")

    def test_verify_otp_using_recovery_codes(self):
        response = self.client.post(
            reverse("mfa:verify_otp"), {"verification_code": "ABcDg"}
        )
        self.assertEquals(response.status_code, 302)
        self.assertEquals(response.url, settings.LOGIN_REDIRECT_URL)

    def test_secret_key_length_not_divisibale_by_8(self):
        with self.assertRaises(binascii.Error):
            secret_key = "secretkey"
            # Here secretkey length is not divisble by 8 so we get error
            totp.TOTP(secret_key).now()

    def test_verify_otp_using_otp(self):
        key = UserOTP.objects.get(user=self.user)
        token = totp.TOTP(key.secret_key).now()
        response = self.client.post(
            reverse("mfa:verify_otp"), {"verification_code": token}
        )
        self.assertEquals(response.status_code, 302)
        self.assertEquals(response.url, settings.LOGIN_REDIRECT_URL)
        settings.MFA_REMEMBER_MY_BROWSER = True
        settings.MFA_REMEMBER_DAYS = 2
        token = totp.TOTP(key.secret_key).now()
        response = self.client.post(
            reverse("mfa:verify_otp"), {"verification_code": token}
        )
        self.assertEquals(response.status_code, 302)
        self.assertEquals(response.url, settings.LOGIN_REDIRECT_URL)

    def test_verify_mfa_wrong_code(self):
        response = self.client.post(
            reverse("mfa:verify_otp"), {"verification_code": "WrongToken"}
        )
        self.assertEquals(
            response.context["error_message"], "Your code is expired or invalid."
        )

    def test_verify_otp_missing_token(self):
        """
        Test posting without a verification code
        """
        response = self.client.post(reverse("mfa:verify_otp"))
        self.assertEquals(
            response.context["error_message"], "Missing verification code."
        )
        self.assertEquals(response.status_code, 400)
        response = self.client.get(reverse("mfa:verify_otp"))
        self.assertNotEquals(response.status_code, 400)
        self.assertTemplateUsed(response, "django_mfa/login_verify.html")

    def test_enable_mfa_false_case_view(self):
        response = self.client.get(reverse("mfa:enable_mfa"))
        self.assertRedirects(
            response, expected_url=reverse("mfa:security_settings"), status_code=302
        )

    def test_recovery_codes_already_generated_view(self):
        response = self.client.get(reverse("mfa:recovery_codes"))
        self.assertTemplateUsed(response, "django_mfa/recovery_codes.html")

    def test_recovery_codes_newcodes_generate_view(self):
        UserRecoveryCodes.objects.get(
            user=UserOTP.objects.get(user=auth.get_user(self.client)),
            secret_code="ABcDg",
        ).delete()
        response = self.client.get(reverse("mfa:recovery_codes"))
        self.assertTemplateUsed(response, "django_mfa/recovery_codes.html")

    def test_recovery_codes_download_view(self):
        response = self.client.get(reverse("mfa:recovery_codes_download"))
        self.assertEquals(response.status_code, 200)

    def test_disable_mfa_view(self):
        response = self.client.get(reverse("mfa:disable_mfa"))
        self.assertTemplateUsed(response, "django_mfa/disable_mfa.html")

        # post failure case
        otp_code = "random25235"
        data = {"verification_code": otp_code}
        response = self.client.post(reverse("mfa:disable_mfa"), data=data)
        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed(response, "django_mfa/disable_mfa.html")

        # post success case
        data["verification_code"] = "abcdefg"
        response = self.client.post(reverse("mfa:disable_mfa"), data=data)
        self.assertRedirects(
            response, expected_url=reverse("mfa:configure_mfa"), status_code=302
        )


class Views_test_not_auth_factor(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="djangomfa@mp.com", email="djangomfa@mp.com", password="djangomfa"
        )
        self.client.login(username="djangomfa@mp.com", password="djangomfa")

    def test_configure_mfa_view_post_method(self):
        response = self.client.post(reverse("mfa:configure_mfa"))
        self.assertTemplateUsed(response, "django_mfa/configure.html")

    def test_enable_mfa_view(self):
        response = self.client.get(reverse("mfa:enable_mfa"))
        self.assertTemplateUsed(response, "django_mfa/configure.html")

    def test_enable_mfa__false_view(self):
        response = self.client.post(
            reverse("mfa:enable_mfa"),
            {
                "secret_key": ["GHAGKUZTB7QNP4XP"],
                "verification_code": ["232988"],
                "otp_type": ["TOTP"],
            },
        )
        self.assertTemplateUsed(response, "django_mfa/configure.html")

    def test_disable_mfa_view(self):
        response = self.client.get(reverse("mfa:disable_mfa"), follow=True)
        self.assertTemplateUsed(response, "django_mfa/configure.html")

    def test_recovery_codes_view(self):
        response = self.client.get(reverse("mfa:recovery_codes"))
        self.assertEquals(response.status_code, 200)

    def test_app_file(self):
        self.assertEqual(DjangoMfaAppConfig.name, "django_mfa")

    def test_enable_mfa(self):
        secret_key = "ABCDEFGH"
        token = totp.TOTP(secret_key).now()
        response = self.client.post(
            reverse("mfa:enable_mfa"),
            {"verification_code": token, "secret_key": secret_key, "otp_type": "TOTP"},
        )
        self.assertEquals(response.status_code, 302)
        self.assertEquals(response.url, reverse("mfa:recovery_codes"))
