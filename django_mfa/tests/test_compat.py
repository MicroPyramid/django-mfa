from django.test import TestCase


class ImportCompatTests(TestCase):
    def test_views_import_on_modern_django(self):
        """views.py must not import symbols removed in Django 4.0."""
        import django_mfa.views  # noqa: F401

    def test_no_removed_symbols_referenced(self):
        import inspect
        import django_mfa.views as views

        source = inspect.getsource(views)
        self.assertNotIn("is_safe_url", source)
        self.assertNotIn("ugettext", source)
