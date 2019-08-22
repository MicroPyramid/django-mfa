from unittest import skip

from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
try:
    from django.core.urlresolvers import reverse
except Exception:
    from django.urls import reverse
from django.test import Client, TestCase
from django_mfa import totp
from django_mfa.models import is_mfa_enabled, UserOTP


class Views_test(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='micro', email='djangomfa@mp.com', password='djangomfa')
        self.client.login(username='micro', password="djangomfa")

    # def test_security_settings_view(self):
    #     response = self.client.get(reverse('mfa:security_settings'))
    #     self.assertTemplateUsed(response, "django_mfa/security.html")

    # def test_configure_mfa_view(self):
    #     response = self.client.get(reverse('mfa:configure_mfa'))
    #     self.assertTemplateUsed(response, "django_mfa/configure.html")

    # @skip('Need to implement')
    # def test_verify_otp(self):
    #     """
    #     Test posting with a valid verification token
    #     """
    #     pass

    # def test_verify_otp_missing_token(self):
    #     """
    #     Test posting without a verification code
    #     """
    #     response = self.client.post(reverse('mfa:verify_otp'))

    #     self.assertEquals(response.context['error_message'], 'Missing verification code.')
    #     self.assertEquals(response.status_code, 400)

    def test_login_redirect_persists_after_failed_otp_verify(self):
        login_redirect = '/some_other_url'
        UserOTP.objects.create(user=self.user, otp_type='totp')
        response = self.client.post(reverse('mfa:verify_otp'), {'verification_code': 'Bad Code',  'next': login_redirect })

        self.assertEqual(response.status_code, 400)
        self.assertTrue(login_redirect in response.content)
