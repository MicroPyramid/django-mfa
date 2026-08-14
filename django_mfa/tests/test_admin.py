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
import time

from django.contrib import admin
from django.contrib.auth.models import Permission, User
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import reverse

from django_mfa import session
from django_mfa.admin_site import protect_admin_site
from django_mfa.models import Authenticator

SECRET = "JBSWY3DPEHPK3PXPCANARY"

# test_runner.py's MIDDLEWARE, minus MfaMiddleware. ProtectedAdminTests and
# AdminStepUpTests use this deliberately: the admin's own headline claim is
# that it holds with NO middleware installed at all, and the suite's default
# MIDDLEWARE includes MfaMiddleware -- which, combined with MFA_PROTECT_ADMIN
# making policy.resolve() effectively cover is_staff users, would produce
# every asserted redirect on its own regardless of whether protect_admin_site()
# does anything. Without this override those tests pass even with the patch
# suppressed entirely (verified: fix round 1, Finding 3).
NO_MFA_MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]


class FakeRequest:
    """The minimal object session.mark_verified() needs: something with a
    mutable .session. Lets a test drive the real session store behind
    self.client (a SessionStore, not a plain dict) through session.py's own
    API rather than writing to request.session["mfa"] directly -- session.py
    is the only module allowed to touch that key's shape.
    """

    def __init__(self, session):
        self.session = session


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


@override_settings(ROOT_URLCONF="django_mfa.tests.support.protected_admin_urls",
                   MFA_PROTECT_ADMIN=True, MIDDLEWARE=NO_MFA_MIDDLEWARE)
class ProtectedAdminTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_superuser(
            "staff@example.com", "staff@example.com", "pw")
        Authenticator.objects.create(
            user=self.staff, type="totp", data={"secret": SECRET})
        protect_admin_site(admin.site)
        self.addCleanup(self._unpatch)

    def _unpatch(self):
        # admin.site is a django.utils.functional.LazyObject (see
        # django.contrib.admin.sites.DefaultAdminSite): its own __dict__
        # holds nothing but `_wrapped`, and every attribute set through the
        # proxy -- including protect_admin_site()'s patches -- lands on the
        # real AdminSite instance underneath. Popping from admin.site.__dict__
        # directly is therefore a silent no-op that leaves the patch in
        # place for every later test.
        real_site = admin.site._wrapped
        for attr in ("has_permission", "login", "_django_mfa_protected"):
            real_site.__dict__.pop(attr, None)

    def _verify(self):
        s = self.client.session
        session.mark_verified(FakeRequest(s), "totp")
        s.save()

    def test_unverified_staff_cannot_reach_the_admin_index(self):
        self.client.force_login(self.staff)
        response = self.client.get(reverse("admin:index"))
        self.assertEqual(response.status_code, 302)

    def test_unverified_staff_land_on_mfa_verify_not_the_admin_login_form(self):
        """django-two-factor-auth's long-standing wart: an already
        authenticated user being shown a login form.

        startswith, not exact equality: the redirect carries a `?next=...`
        query string (enforcement_redirect()'s own doing, via
        redirect_to_login()), so the redirect-chain entry is never exactly
        equal to the bare reverse()'d path.
        """
        self.client.force_login(self.staff)
        response = self.client.get(reverse("admin:index"), follow=True)
        self.assertTrue(any(
            url.startswith(reverse("mfa:verify"))
            for url, _ in response.redirect_chain))

    def test_verified_staff_get_in(self):
        self.client.force_login(self.staff)
        self._verify()
        self.assertEqual(
            self.client.get(reverse("admin:index")).status_code, 200)

    def test_factorless_staff_are_sent_to_the_security_page(self):
        Authenticator.objects.filter(user=self.staff).delete()
        self.client.force_login(self.staff)
        response = self.client.get(reverse("admin:index"), follow=True)
        self.assertTrue(any(
            url.startswith(reverse("mfa:security_settings"))
            for url, _ in response.redirect_chain))

    def test_anonymous_still_sees_the_normal_admin_login_form(self):
        self.assertEqual(
            self.client.get(reverse("admin:login")).status_code, 200)

    def test_patching_twice_is_a_no_op(self):
        before = admin.site.has_permission
        protect_admin_site(admin.site)
        self.assertIs(admin.site.has_permission, before)

    def test_login_view_still_declares_itself_login_not_required(self):
        """Fix round 1, Finding 1 (and fix round 2: the first version of this
        test was a false safety net -- see below).

        AdminSite.login is decorated @login_not_required (Django >= 5.1),
        and LoginRequiredMiddleware reads that marker off the URL pattern's
        callable -- not off the AdminSite instance -- to decide whether an
        anonymous request may reach admin:login at all. Critically, the
        middleware's own default for a MISSING marker is `True` (i.e.
        "login required"):

            if not getattr(view_func, "login_required", True): ...

        so an absent attribute is the FAILURE mode, not a safe stand-in for
        an explicit False -- exactly what the reviewer's empirical run
        showed (`login_required attr: MISSING` -> 302 away from the login
        page). protect_admin_site()'s replacement view must therefore carry
        the ORIGINAL's marker forward via functools.update_wrapper(), and
        this test has to compare against that original rather than hard-
        coding an expectation, or `getattr(..., False)` masks exactly the
        regression it exists to catch (a bare `assertIsNot(..., True)`
        against a default of False passes whether or not the attribute
        survived the patch -- verified by mutation, see the round-2 report
        entry).

        Comparing against AdminSite.login directly (not a hard-coded
        True/False/absent) keeps this correct across the Django floor: on
        >= 5.1 both sides are False; on 4.2, where LoginRequiredMiddleware
        does not exist, both sides are equally absent and the comparison
        passes trivially -- which is correct, since there is nothing to
        protect against on that version.
        """
        from django.contrib.admin.sites import AdminSite

        missing = object()
        self.assertEqual(
            getattr(admin.site.login, "login_required", missing),
            getattr(AdminSite.login, "login_required", missing))


@override_settings(ROOT_URLCONF="django_mfa.tests.support.protected_admin_urls",
                   MFA_PROTECT_ADMIN=True, MFA_ADMIN_STEPUP=True,
                   MFA_STEPUP_MAX_AGE=60, MIDDLEWARE=NO_MFA_MIDDLEWARE)
class AdminStepUpTests(TestCase):
    """MFA_ADMIN_STEPUP -- fix round 1, Finding 4. Untested before this: the
    re-prompt after MFA_STEPUP_MAX_AGE is the one piece of _login_redirect()
    not delegated wholesale to decorators.enforcement_redirect().
    """

    def setUp(self):
        self.staff = User.objects.create_superuser(
            "stepup@example.com", "stepup@example.com", "pw")
        Authenticator.objects.create(
            user=self.staff, type="totp", data={"secret": SECRET})
        protect_admin_site(admin.site)
        self.addCleanup(self._unpatch)
        self.client.force_login(self.staff)

    def _unpatch(self):
        real_site = admin.site._wrapped
        for attr in ("has_permission", "login", "_django_mfa_protected"):
            real_site.__dict__.pop(attr, None)

    def _verify_at(self, at):
        s = self.client.session
        session.mark_verified(FakeRequest(s), "totp")
        state = s["mfa"]
        state["at"] = at
        s["mfa"] = state
        s.save()

    def test_a_fresh_challenge_is_admitted(self):
        self._verify_at(int(time.time()))
        self.assertEqual(
            self.client.get(reverse("admin:index")).status_code, 200)

    def test_a_stale_challenge_is_sent_back_through_verify(self):
        # MFA_STEPUP_MAX_AGE=60 above; 120s old is comfortably past it.
        self._verify_at(int(time.time()) - 120)
        response = self.client.get(reverse("admin:index"), follow=True)
        self.assertTrue(any(
            url.startswith(reverse("mfa:verify"))
            for url, _ in response.redirect_chain))


@override_settings(ROOT_URLCONF="django_mfa.tests.support.admin_urls")
class UnprotectedAdminTests(TestCase):
    def test_admin_is_untouched_when_the_setting_is_off(self):
        staff = User.objects.create_superuser(
            "s2@example.com", "s2@example.com", "pw")
        self.client.force_login(staff)
        self.assertEqual(
            self.client.get(reverse("admin:index")).status_code, 200)
