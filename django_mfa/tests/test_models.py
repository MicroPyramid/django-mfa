from django.contrib.auth.models import User
from django.db.utils import IntegrityError
from django.test import TestCase

from django_mfa.models import Authenticator


class AuthenticatorTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")

    def test_one_totp_per_user(self):
        Authenticator.objects.create(user=self.user, type=Authenticator.Type.TOTP)
        with self.assertRaises(IntegrityError):
            Authenticator.objects.create(user=self.user, type=Authenticator.Type.TOTP)

    def test_many_webauthn_per_user(self):
        Authenticator.objects.create(user=self.user,
                                     type=Authenticator.Type.WEBAUTHN, name="key 1")
        Authenticator.objects.create(user=self.user,
                                     type=Authenticator.Type.WEBAUTHN, name="key 2")
        self.assertEqual(self.user.mfa_authenticators.count(), 2)

    def test_record_usage_sets_last_used_at(self):
        auth = Authenticator.objects.create(user=self.user,
                                            type=Authenticator.Type.TOTP)
        self.assertIsNone(auth.last_used_at)
        auth.record_usage()
        auth.refresh_from_db()
        self.assertIsNotNone(auth.last_used_at)

    def test_for_user_returns_only_that_users_authenticators(self):
        other = User.objects.create_user("b@example.com", password="pw")
        mine = Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP)
        Authenticator.objects.create(user=other, type=Authenticator.Type.TOTP)
        self.assertEqual(list(Authenticator.objects.for_user(self.user)), [mine])


class LegacyModelRemovalTests(TestCase):
    def test_legacy_models_are_gone(self):
        import django_mfa.models as models

        for name in ("UserOTP", "UserRecoveryCodes", "U2FKey"):
            self.assertFalse(hasattr(models, name), f"{name} should be removed")

    def test_authenticator_is_the_only_registered_model(self):
        # Note: MfaUserHandle (django_mfa/handles.py, added by Task 15 for the
        # stored WebAuthn user handle) is also registered under the django_mfa
        # app label. The original brief predates that addition and asserted
        # {"Authenticator"} alone; the task-20 instructions explicitly say
        # Authenticator and MfaUserHandle are the only models the app
        # registers, so that is what this test checks.
        from django.apps import apps

        names = {m.__name__ for m in apps.get_app_config("django_mfa").get_models()}
        self.assertEqual(names, {"Authenticator", "MfaUserHandle"})
