# django_mfa/tests/test_sandbox_smoke.py
#
# Not actually about the sandbox app (that has no automated test coverage --
# see task-19-report.md for why a Django TestCase can't drive `manage.py
# runserver` in a meaningful way). This guards the one thing task 19 can
# reliably pin with a unit test: every setting `conf.DEFAULTS` exposes has a
# matching entry in the documentation, so a future setting can never ship
# undocumented the way the FIDO2 block briefly did during this task.
from django.test import TestCase


class SettingsDocumentationTests(TestCase):
    def test_every_setting_is_documented(self):
        from django_mfa.conf import DEFAULTS

        with open("docs/installation_setup.rst") as handle:
            docs = handle.read()

        undocumented = [name for name in DEFAULTS if name not in docs]
        self.assertEqual(undocumented, [], f"Undocumented settings: {undocumented}")
