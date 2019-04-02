from unittest import skip
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
try:
    from django.core.urlresolvers import reverse
except Exception:
    from django.urls import reverse
from django.test import Client, TestCase
from django_mfa import totp
from django_mfa.models import *
from django.conf import settings


class Views_test_auth_factor(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='micro', email='djangomfa@mp.com', password='djangomfa')
        UserOTP.objects.create(
            otp_type='TOTP', user=self.user, secret_key='secret_key')
        self.session = self.client.session
        UserRecoveryCodes.objects.create(user=UserOTP.objects.get(
            user=self.user), secret_code="ABcDg")
        session = self.client.session
        session['verfied_otp'] = True
        session.save()
        self.client.login(username='micro', password="djangomfa")

    def test_middleware_with_Securitysettings_view(self):
        session = self.client.session
        session['verfied_otp'] = False
        session.save()
        response = self.client.get(reverse('mfa:security_settings'))
        url = reverse('mfa:verify_otp') + \
            "?next=" + reverse('mfa:security_settings')
        self.assertEquals(
            response.url, url)

    def test_verify_rmb_cookie_with_Securitysettings_view(self):
        settings.MFA_REMEMBER_MY_BROWSER = True
        settings.MFA_REMEMBER_DAYS = 2
        response = self.client.get(reverse('mfa:security_settings'))
        self.assertEquals(response.status_code, 200)

    def test_security_settings_view(self):
        response = self.client.get(reverse('mfa:security_settings'))
        self.assertTemplateUsed(response, "django_mfa/security.html")

    def test_configure_mfa_view(self):
        response = self.client.get(reverse('mfa:configure_mfa'))
        self.assertTemplateUsed(response, "django_mfa/configure.html")

    def test_verify_otp_using_recovery_codes(self):
        response = self.client.post(reverse('mfa:verify_otp'), {
                                    'verification_code': "ABcDg"})
        self.assertEquals(response.status_code, 302)
        self.assertEquals(response.url, settings.LOGIN_REDIRECT_URL)

    # @skip('Need to implement')
    # def test_verify_otp(self):
    #     """
    #     Test posting with a valid verification token
    #     """
    #     pass

    def test_verify_otp_missing_token(self):
        """
        Test posting without a verification code
        """
        response = self.client.post(reverse('mfa:verify_otp'))
        self.assertEquals(
            response.context['error_message'], 'Missing verification code.')
        self.assertEquals(response.status_code, 400)

    def test_enable_mfa_false_case_view(self):
        response = self.client.get(reverse('mfa:enable_mfa'))
        self.assertRedirects(
            response, expected_url=reverse('mfa:disable_mfa'), status_code=302)

    def test_recovery_codes_already_generated_view(self):
        response = self.client.get(reverse('mfa:recovery_codes'))
        self.assertTemplateUsed(response, "django_mfa/recovery_codes.html")

    def test_recovery_codes_newcodes_generate_view(self):
        UserRecoveryCodes.objects.get(user=UserOTP.objects.get(
            user=self.user), secret_code="ABcDg").delete()
        response = self.client.get(reverse('mfa:recovery_codes'))
        self.assertTemplateUsed(response, "django_mfa/recovery_codes.html")

    def test_recovery_codes_download_view(self):
        response = self.client.get(reverse('mfa:recovery_codes_download'))
        self.assertEquals(
            response.status_code, 200)

    def test_disable_mfa_view(self):
        response = self.client.get(reverse('mfa:disable_mfa'))
        self.assertTemplateUsed(response, "django_mfa/disable_mfa.html")
        response = self.client.post(reverse('mfa:disable_mfa'))
        self.assertRedirects(
            response, expected_url=reverse('mfa:configure_mfa'), status_code=302)


class Views_test_not_auth_factor(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='micro', email='djangomfa@mp.com', password='djangomfa')
        self.client.login(username='micro', password="djangomfa")

    def test_configure_mfa_view_post_method(self):
        response = self.client.post(reverse('mfa:configure_mfa'))
        self.assertTemplateUsed(response, "django_mfa/configure.html")

    def test_enable_mfa_view(self):
        response = self.client.get(reverse('mfa:enable_mfa'))
        self.assertTemplateUsed(response, "django_mfa/configure.html")

    def test_enable_mfa__false_view(self):
        response = self.client.post(reverse('mfa:enable_mfa'), {
                                    "secret_key": ['GHAGKUZTB7QNP4XP'], "verification_code": ['232988'], "otp_type": ['TOTP']})
        self.assertTemplateUsed(response, "django_mfa/configure.html")

    def test_disable_mfa_view(self):
        response = self.client.get(reverse('mfa:disable_mfa'), follow=True)
        self.assertTemplateUsed(response, "django_mfa/configure.html")

    def test_recovery_codes_view(self):
        response = self.client.get(reverse('mfa:recovery_codes'))
        self.assertEquals(response.content,
                          b'please enable twofactor_authentication!')
