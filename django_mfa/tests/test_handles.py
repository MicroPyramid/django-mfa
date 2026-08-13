import uuid

from django.contrib.auth.models import User
from django.test import TestCase, override_settings

from django_mfa.handles import MfaUserHandle, user_from_handle, user_handle_for


class UserHandleTests(TestCase):
    def setUp(self):
        self.user_a = User.objects.create_user("a@example.com", password="pw")
        self.user_b = User.objects.create_user("b@example.com", password="pw")

    def test_handle_does_not_contain_the_username(self):
        handle = user_handle_for(self.user_a)
        self.assertNotIn("a@example.com", handle)
        self.assertNotIn("a", handle.split("-"))

    def test_handle_is_a_uuid_string(self):
        handle = user_handle_for(self.user_a)
        # Round-trips through uuid.UUID without raising -- confirms it's
        # opaque structured data, not a signed/derived token with its own
        # format.
        uuid.UUID(handle)

    def test_handle_is_unchanged_across_repeated_calls(self):
        first = user_handle_for(self.user_a)
        second = user_handle_for(self.user_a)
        third = user_handle_for(self.user_a)
        self.assertEqual(first, second)
        self.assertEqual(second, third)
        # Only one row was created, not a fresh one per call.
        self.assertEqual(
            MfaUserHandle.objects.filter(user=self.user_a).count(), 1)

    def test_handle_is_stable_across_a_username_change(self):
        handle = user_handle_for(self.user_a)
        self.user_a.username = "renamed@example.com"
        self.user_a.save()
        self.assertEqual(user_handle_for(self.user_a), handle)

    def test_handle_minted_for_one_user_never_resolves_to_another(self):
        handle_a = user_handle_for(self.user_a)
        handle_b = user_handle_for(self.user_b)
        self.assertNotEqual(handle_a, handle_b)
        self.assertEqual(user_from_handle(handle_a), self.user_a)
        self.assertEqual(user_from_handle(handle_b), self.user_b)
        self.assertNotEqual(user_from_handle(handle_a), self.user_b)

    def test_handle_survives_a_secret_key_rotation(self):
        """The whole point of storing the handle instead of signing it.

        A signed-with-SECRET_KEY handle would stop resolving the moment the
        key rotates -- silently breaking passwordless login for every user
        with a passkey, since credentials are registered once and used for
        years. A stored random value has no dependency on any secret.
        """
        handle = user_handle_for(self.user_a)
        with override_settings(SECRET_KEY="a-completely-different-secret-key"):
            self.assertEqual(user_from_handle(handle), self.user_a)

    def test_user_from_handle_returns_none_for_malformed_uuid_string(self):
        self.assertIsNone(user_from_handle("not-a-uuid"))

    def test_user_from_handle_returns_none_for_empty_string(self):
        self.assertIsNone(user_from_handle(""))

    def test_user_from_handle_returns_none_for_none(self):
        self.assertIsNone(user_from_handle(None))

    def test_user_from_handle_returns_none_for_well_formed_unknown_uuid(self):
        self.assertIsNone(user_from_handle(str(uuid.uuid4())))
