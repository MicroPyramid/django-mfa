from django_mfa.models import *
from django.test import TestCase, Client
from django.contrib.auth.models import User


class Test_Models_Mfa(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='micro', email='djangomfa@mp.com', password='djangomfa')
        self.userotp = UserOTP.objects.create(
            otp_type='TOTP', user=self.user, secret_key='secret_key')
        self.user_codes = UserRecoveryCodes.objects.create(user=UserOTP.objects.get(
            user=self.user), secret_code="secret_code")
        self.client.login(username='micro', password="djangomfa")

    def test_mfa_enabled(self):

        self.assertTrue(is_mfa_enabled(self.user))

    def test_user_data_saved_correctly(self):
        user_details = User.objects.filter(id=self.user.id).first()
        self.assertEqual(self.user.username, user_details.username)
        self.assertEqual(self.user.email, user_details.email)
        self.assertEqual(self.user.password, user_details.password)

    def test_userotp_data_saved_correctly(self):
        user_otp = UserOTP.objects.filter(user=self.user).first()
        self.assertEqual(self.userotp.otp_type, user_otp.otp_type)
        self.assertEqual(self.userotp.user, user_otp.user)
        self.assertEqual(self.userotp.secret_key, user_otp.secret_key)

    def test_recovery_codes_generated(self):
        user_codes = UserRecoveryCodes.objects.filter(user=UserOTP.objects.filter(
            user=self.user).first()).first()

        self.assertEqual(self.user_codes, user_codes)
