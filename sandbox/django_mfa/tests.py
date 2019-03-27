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


class Views_test(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='micro', email='djangomfa@mp.com', password='djangomfa')
        UserOTP.objects.create(
            otp_type='TOTP', user=self.user, secret_key='secret_key')
        UserRecoveryCodes.objects.create(user=UserOTP.objects.get(
            user=self.user), secret_code="secret_code")
        self.user.u2f_keys.create(
            public_key='publicKey',
            key_handle='keyHandle',
            app_id='https://appId',
        )
        self.client.login(username='micro', password="djangomfa")

    def test_security_settings_view(self):
        response = self.client.get(reverse('mfa:security_settings'))
        if is_u2f_enabled(self.user) or is_mfa_enabled(self.user):
            url = reverse('mfa:verify_second_factor') + \
                "?next=" + reverse('mfa:security_settings')
            self.assertEquals(
                response.url, url)
        else:
            self.assertTemplateUsed(response, "django_mfa/security.html")

    def test_configure_mfa_view(self):
        response = self.client.get(reverse('mfa:configure_mfa'))
        if is_u2f_enabled(self.user) or is_mfa_enabled(self.user):
            url = reverse('mfa:verify_second_factor') + \
                "?next=" + reverse('mfa:configure_mfa')
            self.assertEquals(
                response.url, url)
        else:
            response = self.client.get(reverse('mfa:configure_mfa'))
            self.assertTemplateUsed(response, "django_mfa/configure.html")

    @skip('Need to implement')
    def test_verify_second_factor_totp(self):
        """
        Test posting with a valid verification token
        """
        pass

    def test_verify_second_factor_totp_missing_token(self):
        """
        Test posting without a verification code
        """
        response = self.client.post(reverse('mfa:verify_second_factor_totp'))

        self.assertEquals(
            response.context['error_message'], 'Missing verification code.')
        self.assertEquals(response.status_code, 400)

        response = self.client.get(reverse('mfa:verify_second_factor_totp'))
        self.assertNotEquals(response.status_code, 400)

    def test_enable_mfa_false_case_view(self):
        response = self.client.get(reverse('mfa:enable_mfa'))
        if is_u2f_enabled(self.user) or is_mfa_enabled(self.user):
            url = reverse('mfa:verify_second_factor') + \
                "?next=" + reverse('mfa:enable_mfa')
            self.assertEquals(
                response.url, url)
        else:
            response = self.client.get(
                reverse('mfa:enable_mfa'), follow=True)
            if is_mfa_enabled(self.user):
                self.assertTemplateUsed(response, "django_mfa/disable.html")
            else:
                self.assertTemplateUsed(response, "django_mfa/configure.html")

    def test_disable_mfa_view(self):
        response = self.client.get(reverse('mfa:disable_mfa'))
        if is_u2f_enabled(self.user) or is_mfa_enabled(self.user):
            url = reverse('mfa:verify_second_factor') + \
                "?next=" + reverse('mfa:disable_mfa')
            self.assertEquals(
                response.url, url)
        else:
            response = self.client.get(
                reverse('mfa:disable_mfa'), follow=True)
            if is_mfa_enabled(self.user):
                self.assertTemplateUsed(response, "django_mfa/disable.html")
            else:
                self.assertTemplateUsed(response, "django_mfa/configure.html")

    def test_recovery_codes_view(self):
        response = self.client.get(reverse('mfa:recovery_codes'))
        if is_u2f_enabled(self.user) or is_mfa_enabled(self.user):
            url = reverse('mfa:verify_second_factor') + \
                "?next=" + reverse('mfa:recovery_codes')
            self.assertEquals(
                response.url, url)
        else:
            if is_mfa_enabled(self.user):
                self.assertTemplateUsed(response, "django_mfa/recovery_codes.html")
            else:
                self.assertEquals(response.content,
                                  b'please enable twofactor_authentication!')

    def test_verify_second_factor_view(self):
        if is_mfa_enabled(self.user) or is_u2f_enabled(self.user):
            response = self.client.get(reverse('mfa:verify_second_factor'))
            self.assertTemplateUsed(
                response, "django_mfa/verify_second_factor.html")

    def test_recovery_codes_download_view(self):
        if is_u2f_enabled(self.user) or is_mfa_enabled(self.user):
            response = self.client.get(reverse('mfa:recovery_codes_download'))
            url = reverse('mfa:verify_second_factor') + \
                "?next=" + reverse('mfa:recovery_codes_download')
            self.assertEquals(
                response.url, url)
        else:
            if is_mfa_enabled(self.user):
                response = self.client.get(reverse('mfa:recovery_codes_download'))
                self.assertTemplateUsed(response, "django_mfa/recovery_codes.html")
                self.assertEquals(response.content,
                                  b'secret_code')

    def test_add_key_view(self):
        response = self.client.get(reverse('mfa:add_u2f_key'))
        if is_u2f_enabled(self.user) or is_mfa_enabled(self.user):
            url = reverse('mfa:verify_second_factor') + \
                "?next=" + reverse('mfa:add_u2f_key')
            self.assertEquals(
                response.url, url)
        else:
            self.assertTemplateUsed(response, "u2f/add_key.html")

    @skip('Need to implement')
    def test_verify_second_factor_u2f_view(self):
        pass

    def test_add_key_view(self):
        response = self.client.get(reverse('mfa:u2f_keys'))
        if is_u2f_enabled(self.user) or is_mfa_enabled(self.user):
            url = reverse('mfa:verify_second_factor') + \
                "?next=" + reverse('mfa:u2f_keys')
            self.assertEquals(
                response.url, url)
        else:
            self.assertTemplateUsed(response, "u2f/key_list.html")
