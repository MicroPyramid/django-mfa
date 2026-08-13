from django.test import TestCase


class U2FCodeRemovalTests(TestCase):
    def test_u2f_forms_module_is_gone(self):
        with self.assertRaises(ImportError):
            import django_mfa.forms  # noqa: F401

    def test_views_no_longer_reference_u2f(self):
        # views.py became a package (django_mfa.views.{picker,verify,enroll,
        # manage}) in Task 12 -- check every submodule, not just __init__.py,
        # so this keeps its original scope of "no view code mentions u2f".
        import inspect

        import django_mfa.views
        import django_mfa.views.enroll
        import django_mfa.views.manage
        import django_mfa.views.picker
        import django_mfa.views.verify

        for module in (django_mfa.views, django_mfa.views.picker,
                      django_mfa.views.verify, django_mfa.views.enroll,
                      django_mfa.views.manage):
            self.assertNotIn("u2f", inspect.getsource(module).lower())

    def test_remaining_totp_urls_still_resolve(self):
        # mfa:configure_mfa was the old UserOTP-driven enrollment URL, removed
        # along with the rest of the legacy views.py (see Task 12). Its
        # replacement is the registry-driven mfa:enroll_factor/verify family.
        from django.urls import reverse

        self.assertTrue(reverse("mfa:security_settings"))
        self.assertTrue(reverse("mfa:verify"))
        self.assertTrue(reverse("mfa:enroll_factor", args=["totp"]))

    def test_removed_u2f_urls_are_gone(self):
        from django.urls import NoReverseMatch, reverse

        for name in ("mfa:u2f_keys", "mfa:add_u2f_key",
                     "mfa:verify_second_factor_u2f"):
            with self.assertRaises(NoReverseMatch):
                reverse(name)
