# django_mfa/tests/test_admin.py
#
# The admin is a privilege-escalation surface for this model specifically.
# Authenticator.data holds the TOTP shared secret, the recovery-code hashes
# and the WebAuthn credential; a default ModelAdmin renders every editable
# field, so any staff account with view permission could read another user's
# TOTP secret (and generate valid codes for them), and one with change
# permission could plant a secret of its own choosing. Note that
# MFA_SECRET_ENCRYPTION_KEYS is no defence here -- django_mfa.crypto signs,
# it does not encrypt, and the payload is recoverable without any key.
from django.contrib import admin
from django.contrib.auth.models import Permission, User
from django.test import Client, RequestFactory, TestCase, override_settings

from django_mfa.models import Authenticator

SECRET = "JBSWY3DPEHPK3PXPCANARY"


class AuthenticatorAdminTests(TestCase):
    def setUp(self):
        self.model_admin = admin.site._registry[Authenticator]
        self.superuser = User.objects.create_superuser(
            "root@example.com", "root@example.com", "pw")
        self.request = RequestFactory().get("/")
        self.request.user = self.superuser
        self.row = Authenticator.objects.create(
            user=self.superuser, type="totp", data={"secret": SECRET})

    def test_the_data_blob_is_not_an_exposed_field(self):
        self.assertNotIn("data", self.model_admin.get_fields(
            self.request, self.row))

    def test_the_data_blob_is_not_in_the_changelist(self):
        self.assertNotIn("data", self.model_admin.get_list_display(self.request))

    def test_no_search_field_can_probe_the_data_blob(self):
        for field in self.model_admin.get_search_fields(self.request):
            self.assertFalse(field.lstrip("^=@$").startswith("data"), field)

    def test_authenticators_cannot_be_added_by_hand(self):
        self.assertFalse(self.model_admin.has_add_permission(self.request))

    def test_authenticators_cannot_be_edited(self):
        self.assertFalse(
            self.model_admin.has_change_permission(self.request, self.row))

    def test_authenticators_can_still_be_deleted(self):
        """Revoking a lost device for a locked-out user is a legitimate and
        necessary support operation. Hardening must not take it away.
        """
        self.assertTrue(
            self.model_admin.has_delete_permission(self.request, self.row))


@override_settings(ROOT_URLCONF="django_mfa.tests.support.admin_urls")
class AuthenticatorAdminHttpTests(TestCase):
    """Drives the real admin over HTTP as a low-privilege staff account --
    the shape an actual insider attack takes.
    """

    def setUp(self):
        self.victim = User.objects.create_superuser(
            "victim@example.com", "victim@example.com", "pw")
        self.row = Authenticator.objects.create(
            user=self.victim, type="totp", data={"secret": SECRET})

        self.staff = User.objects.create_user(
            "staff@example.com", password="pw", is_staff=True)
        for codename in ("view_authenticator", "change_authenticator",
                         "add_authenticator", "delete_authenticator"):
            self.staff.user_permissions.add(
                Permission.objects.get(codename=codename))
        self.client = Client()
        self.client.force_login(self.staff)

    def test_the_change_page_does_not_leak_another_users_secret(self):
        # 200, not a redirect: the page must still render (staff hold view
        # permission, and inspecting an enrolled factor is legitimate) -- so
        # this asserts the secret is absent from a page that really was
        # served, rather than passing on an empty redirect body.
        response = self.client.get(
            f"/admin/django_mfa/authenticator/{self.row.pk}/change/")
        self.assertNotContains(response, SECRET, status_code=200)

    def test_the_changelist_does_not_leak_another_users_secret(self):
        response = self.client.get("/admin/django_mfa/authenticator/")
        self.assertNotContains(response, SECRET)

    def test_posting_a_chosen_secret_does_not_take_effect(self):
        self.client.post(
            f"/admin/django_mfa/authenticator/{self.row.pk}/change/",
            {"user": self.victim.pk, "type": "totp", "name": "",
             "data": '{"secret": "ATTACKERCHOSEN01"}',
             "created_at_0": "2026-01-01", "created_at_1": "00:00:00"})
        self.row.refresh_from_db()
        self.assertEqual(self.row.data["secret"], SECRET)

    def test_the_add_page_is_refused(self):
        response = self.client.get("/admin/django_mfa/authenticator/add/")
        self.assertEqual(response.status_code, 403)

    def test_deleting_a_lost_authenticator_still_works(self):
        response = self.client.post(
            f"/admin/django_mfa/authenticator/{self.row.pk}/delete/",
            {"post": "yes"})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Authenticator.objects.filter(pk=self.row.pk).exists())
