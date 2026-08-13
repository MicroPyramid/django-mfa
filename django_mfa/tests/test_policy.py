from django.contrib.auth.models import Group, User
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings

from django_mfa import policy
from django_mfa.checks import check_mfa_required_predicate


def everyone(user):
    return True


def nobody(user):
    return False


not_callable = "this is a string, not a function"


class MfaRequiredForTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")

    def test_default_requires_nobody(self):
        self.assertFalse(policy.mfa_required_for(self.user))

    @override_settings(MFA_REQUIRED=True)
    def test_true_requires_every_authenticated_user(self):
        self.assertTrue(policy.mfa_required_for(self.user))

    @override_settings(MFA_REQUIRED=True)
    def test_anonymous_is_never_required(self):
        from django.contrib.auth.models import AnonymousUser
        self.assertFalse(policy.mfa_required_for(AnonymousUser()))

    @override_settings(MFA_REQUIRED="django_mfa.tests.test_policy.everyone")
    def test_dotted_path_is_imported_and_called(self):
        self.assertTrue(policy.mfa_required_for(self.user))

    @override_settings(MFA_REQUIRED="django_mfa.tests.test_policy.nobody")
    def test_dotted_path_returning_false(self):
        self.assertFalse(policy.mfa_required_for(self.user))

    @override_settings(MFA_REQUIRED=everyone)
    def test_a_plain_callable_works_too(self):
        self.assertTrue(policy.mfa_required_for(self.user))


class SuppliedPredicateTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")

    @override_settings(MFA_REQUIRED=policy.is_staff)
    def test_is_staff(self):
        self.assertFalse(policy.mfa_required_for(self.user))
        self.user.is_staff = True
        self.assertTrue(policy.mfa_required_for(self.user))

    def test_in_groups_matches_only_named_groups(self):
        predicate = policy.in_groups("admins", "finance")
        with override_settings(MFA_REQUIRED=predicate):
            self.assertFalse(policy.mfa_required_for(self.user))
            self.user.groups.add(Group.objects.create(name="marketing"))
            self.assertFalse(policy.mfa_required_for(self.user))
            self.user.groups.add(Group.objects.create(name="finance"))
            self.assertTrue(policy.mfa_required_for(self.user))

    def test_in_groups_costs_one_query(self):
        predicate = policy.in_groups("admins")
        with self.assertNumQueries(1):
            predicate(self.user)


class CheckE004Tests(TestCase):
    def test_default_passes(self):
        self.assertEqual(check_mfa_required_predicate(None), [])

    @override_settings(MFA_REQUIRED="django_mfa.tests.test_policy.everyone")
    def test_valid_dotted_path_passes(self):
        self.assertEqual(check_mfa_required_predicate(None), [])

    @override_settings(MFA_REQUIRED="django_mfa.nonexistent.predicate")
    def test_unimportable_path_is_an_error(self):
        errors = check_mfa_required_predicate(None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E004"])

    @override_settings(MFA_REQUIRED="django_mfa.tests.test_policy.not_callable")
    def test_importable_but_not_callable_is_an_error(self):
        errors = check_mfa_required_predicate(None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E004"])

    @override_settings(MFA_REQUIRED=42)
    def test_nonsense_value_is_an_error(self):
        errors = check_mfa_required_predicate(None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E004"])

    @override_settings(MFA_REQUIRED="django_mfa.nonexistent.predicate")
    def test_the_check_is_not_gated_on_webauthn(self):
        """E001-E003 are WebAuthn-only and skip for a TOTP-only project.
        E004 is not WebAuthn-specific and must fire regardless."""
        with override_settings(MFA_QUICKLOGIN=False):
            errors = check_mfa_required_predicate(None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E004"])


class ResolveTests(TestCase):
    @override_settings(MFA_REQUIRED=42)
    def test_resolve_raises_on_a_nonsense_value(self):
        with self.assertRaises(ImproperlyConfigured):
            policy.resolve()
