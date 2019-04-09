from django_mfa.models import *
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.contrib import auth

class Test_Models_Mfa_U2f(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='djangomfa@mp.com', email='djangomfa@mp.com', password='djangomfa')
        self.userotp = UserOTP.objects.create(
            otp_type='TOTP', user=self.user, secret_key='secret_key')
        self.user_codes = UserRecoveryCodes.objects.create(user=UserOTP.objects.get(
            user=self.user), secret_code="secret_code")
        self.u2f_keys = self.user.u2f_keys.create(
            public_key='publicKey',
            key_handle='keyHandle',
            app_id='https://appId',
        )
        self.client.login(username='djangomfa@mp.com', password="djangomfa")

    def test_mfa_enabled(self):

        self.assertTrue(is_mfa_enabled(self.user))

    def test_u2f_enabled(self):

        self.assertTrue(is_u2f_enabled(self.user))

    def test_user_data_saved_correctly(self):
        user_details = auth.get_user(self.client)
        self.assertEqual(self.user.username, user_details.username)
        self.assertEqual(self.user.email, user_details.email)
        self.assertEqual(self.user.password, user_details.password)

    def test_userotp_data_saved_correctly(self):
        user_otp = UserOTP.objects.filter(user=self.user).first()
        self.assertEqual(self.userotp.otp_type, user_otp.otp_type)
        self.assertEqual(self.userotp.user, user_otp.user)
        self.assertEqual(self.userotp.secret_key, user_otp.secret_key)

    def test_u2f_key_user(self):
        user_u2f = U2FKey.objects.filter(user=self.user).first()
        self.assertEqual(self.u2f_keys.user, user_u2f.user)
        self.assertEqual(self.u2f_keys.public_key, user_u2f.public_key)
        self.assertEqual(self.u2f_keys.key_handle, user_u2f.key_handle)
        self.assertEqual(self.u2f_keys.app_id, user_u2f.app_id)

    def test_u2f_to_json_function(self):
        user_u2f = U2FKey.objects.filter(user=self.user).first()
        self.assertEqual(self.u2f_keys.to_json(),user_u2f.to_json())

    def test_recovery_codes_generated(self):
        user_codes = UserRecoveryCodes.objects.filter(user=UserOTP.objects.filter(
            user=self.user).first()).first()

        self.assertEqual(self.user_codes, user_codes)
