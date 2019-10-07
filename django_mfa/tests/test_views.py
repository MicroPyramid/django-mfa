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
from django.contrib import auth


class Views_test_auth_factor(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='djangomfa@mp.com', email='djangomfa@mp.com', password='djangomfa')
        UserOTP.objects.create(
            otp_type='TOTP', user=self.user, secret_key='secret_key')
        self.session = self.client.session
        UserRecoveryCodes.objects.create(user=UserOTP.objects.get(
            user=self.user), secret_code="ABcDg")
        self.u2f = self.user.u2f_keys.create(
            public_key='publicKey',
            key_handle='keyHandle',
            app_id='https://appId',
        )
        session = self.client.session
        session['verfied_otp'] = True
        session['verfied_u2f'] = True
        session.save()
        self.client.login(username='djangomfa@mp.com', password="djangomfa")

    def test_middleware_with_Securitysettings_view(self):
        session = self.client.session
        session['verfied_otp'] = False
        session['verfied_u2f'] = False
        session.save()
        response = self.client.get(reverse('mfa:security_settings'))
        url = reverse('mfa:verify_second_factor') + \
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

    def test_verify_second_factor_totp_using_recovery_codes(self):
        response = self.client.post(reverse('mfa:verify_second_factor_totp'), {
                                    'verification_code': "ABcDg"})
        self.assertEquals(response.status_code, 302)
        self.assertEquals(response.url, settings.LOGIN_REDIRECT_URL)

    # @skip('Need to implement')
    # def test_verify_second_factor_totp_using_auth_codes(self):
    #     """
    #     Test posting with a valid verification token
    #     """
    #     pass

    def test_verify_second_factor_u2f_view(self):
        session = self.client.session
        session['verfied_otp'] = False
        session['verfied_u2f'] = False
        session.save()
        response = self.client.get(
            reverse('mfa:verify_second_factor_u2f'), follow=True)
        url = reverse('mfa:verify_second_factor') + \
            "?next=" + settings.LOGIN_URL
        self.assertRedirects(
            response, expected_url=url, status_code=302)

        session['u2f_pre_verify_user_pk'] = auth.get_user(self.client).id
        session['u2f_pre_verify_user_backend'] = 'django.contrib.auth.backends.ModelBackend'
        session.save()
        response = self.client.get(reverse('mfa:verify_second_factor_u2f'))
        self.assertTemplateUsed(response, "u2f/verify_second_factor_u2f.html")

        #  TODO : Need to Implement for Post Method

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
        self.assertRedirects(
            response, expected_url=reverse('mfa:disable_mfa'), status_code=302)

    def test_recovery_codes_already_generated_view(self):
        response = self.client.get(reverse('mfa:recovery_codes'))
        self.assertTemplateUsed(response, "django_mfa/recovery_codes.html")

    def test_recovery_codes_newcodes_generate_view(self):
        UserRecoveryCodes.objects.get(user=UserOTP.objects.get(
            user=auth.get_user(self.client)), secret_code="ABcDg").delete()
        response = self.client.get(reverse('mfa:recovery_codes'))
        self.assertTemplateUsed(response, "django_mfa/recovery_codes.html")

    def test_verify_second_factor_view(self):
        response = self.client.get(reverse('mfa:verify_second_factor'))
        self.assertTemplateUsed(
            response, "django_mfa/verify_second_factor.html")

    def test_recovery_codes_download_view(self):
        response = self.client.get(reverse('mfa:recovery_codes_download'))
        self.assertEquals(
            response.status_code, 200)

    def test_add_key_view(self):
        response = self.client.get(reverse('mfa:add_u2f_key'))
        self.assertTemplateUsed(response, "u2f/add_key.html")

    def test_key_list_view(self):
        response = self.client.get(reverse('mfa:u2f_keys'))
        self.assertTemplateUsed(response, "u2f/key_list.html")
        response = self.client.post(reverse('mfa:u2f_keys'), {
                                    "key_id": self.u2f.id, "delete": True})
        self.assertEquals(response.status_code, 302)
        self.assertEquals(response.url, reverse('mfa:u2f_keys'))

    def test_disable_mfa_view(self):
        response = self.client.get(reverse('mfa:disable_mfa'))
        self.assertTemplateUsed(response, "django_mfa/disable_mfa.html")
        response = self.client.post(reverse('mfa:disable_mfa'))
        self.assertEquals(response.url, settings.LOGIN_REDIRECT_URL)


class Views_test_not_auth_factor(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='djangomfa@mp.com', email='djangomfa@mp.com', password='djangomfa')
        self.client.login(username='djangomfa@mp.com', password="djangomfa")

    def test_configure_mfa_view_post_method(self):
        response = self.client.post(reverse('mfa:configure_mfa'))
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

    def test_enable_mfa_view(self):
        response = self.client.get(reverse('mfa:enable_mfa'))
        self.assertTemplateUsed(response, "django_mfa/configure.html")


class Views_test_auth_factor_new(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='djangomfa@mp.com', email='djangomfa@mp.com', password='djangomfa')
        self.u2f = self.user.u2f_keys.create(
            public_key='publicKey',
            key_handle='keyHandle',
            app_id='https://appId',
        )
        self.u2f1 = self.user.u2f_keys.create(
            public_key='publicKey1',
            key_handle='keyHandle1',
            app_id='https://appId1',
        )
        session = self.client.session
        session['verfied_otp'] = True
        session['verfied_u2f'] = True
        session.save()
        self.client.login(username='djangomfa@mp.com', password="djangomfa")

    def test_key_list_view(self):
        response = self.client.get(reverse('mfa:u2f_keys'))
        self.assertTemplateUsed(response, "u2f/key_list.html")
        response = self.client.post(reverse('mfa:u2f_keys'), {
                                    "key_id": self.u2f1.id, "delete": True})
        self.assertEquals(response.status_code, 302)
        self.assertEquals(response.url, reverse('mfa:u2f_keys'))
