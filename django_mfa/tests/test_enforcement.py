from django.contrib.auth import login as auth_login
from django.contrib.auth.models import User
from django.contrib.sessions.backends.db import SessionStore
from django.core.cache import cache
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import reverse

from django_mfa import totp as totp_mod
from django_mfa.models import Authenticator


class EnforcementTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.client = Client()

    def test_user_without_factors_is_not_challenged(self):
        self.client.login(username="a@example.com", password="pw")
        self.assertNotIn("mfa", self.client.session)

    def test_login_signal_marks_pending_when_factors_exist(self):
        Authenticator.objects.create(user=self.user, type="totp")
        self.client.login(username="a@example.com", password="pw")
        self.assertFalse(self.client.session["mfa"]["verified"])

    def test_recovery_codes_alone_do_not_trigger_a_challenge(self):
        Authenticator.objects.create(user=self.user, type="recovery_codes")
        self.client.login(username="a@example.com", password="pw")
        self.assertNotIn("mfa", self.client.session)

    def test_unverified_request_redirects_to_picker(self):
        Authenticator.objects.create(user=self.user, type="totp")
        self.client.login(username="a@example.com", password="pw")
        response = self.client.get(reverse("mfa:security_settings"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("mfa:verify"), response.url)

    def test_picker_itself_is_exempt(self):
        Authenticator.objects.create(user=self.user, type="totp")
        self.client.login(username="a@example.com", password="pw")
        response = self.client.get(reverse("mfa:verify"))
        self.assertEqual(response.status_code, 302)  # single factor -> redirect
        self.assertIn("totp", response.url)

    def test_factor_verify_page_is_exempt(self):
        Authenticator.objects.create(user=self.user, type="totp")
        self.client.login(username="a@example.com", password="pw")
        response = self.client.get(reverse("mfa:verify_factor", args=["totp"]))
        self.assertEqual(response.status_code, 200)

    def test_verified_session_passes_through(self):
        Authenticator.objects.create(user=self.user, type="totp")
        self.client.login(username="a@example.com", password="pw")
        session = self.client.session
        session["mfa"] = {"verified": True, "method": "totp", "at": 0}
        session.save()
        response = self.client.get(reverse("mfa:security_settings"))
        self.assertEqual(response.status_code, 200)


@override_settings(MFA_REMEMBER_MY_BROWSER=True, MFA_REMEMBER_DAYS=30)
class RememberMyBrowserEnforcementTests(TestCase):
    """Fix round 1, finding 1: MFA_REMEMBER_MY_BROWSER was retained by the
    spec but ended up wired to nothing -- verify_factor never set the
    cookie, and the login signal never checked it. Both halves are now
    connected: verify_factor sets the cookie on success (see
    views/verify.py), and the login signal short-circuits straight to
    verified when a trusted cookie is present (see signals.py)."""

    def setUp(self):
        cache.clear()  # rate-limit counters are keyed by user pk; sqlite can
        # reuse pks across TestCase-rolled-back transactions.
        self.secret = "JBSWY3DPEHPK3PXP"
        self.user = User.objects.create_user("a@example.com", password="pw")
        Authenticator.objects.create(user=self.user, type="totp",
                                     data={"secret": self.secret})
        self.client = Client()

    def _verify_and_get_cookie(self):
        self.client.login(username="a@example.com", password="pw")
        response = self.client.post(
            reverse("mfa:verify_factor", args=["totp"]),
            {"code": totp_mod.TOTP(self.secret).now()})
        cookie_name = "RMB_%d" % self.user.pk
        self.assertIn(cookie_name, response.cookies)
        return cookie_name, response.cookies[cookie_name].value

    def _login_with_cookies(self, cookies):
        """Simulate a fresh browser login carrying `cookies`.

        Client.login() is deliberately not used here: it fabricates a bare
        HttpRequest with empty COOKIES and calls django.contrib.auth.login()
        against that, so it can never carry a real browser cookie into the
        user_logged_in signal. A real request, arriving through
        SessionMiddleware/AuthenticationMiddleware, would carry whatever
        cookies the browser sent -- this reproduces that.
        """
        request = RequestFactory().get("/")
        request.COOKIES = cookies
        request.session = SessionStore()
        # Explicit backend: task 19 added a second entry to
        # AUTHENTICATION_BACKENDS (WebAuthnBackend, ahead of ModelBackend --
        # see test_runner.py) so django_mfa.checks.E003 has something to
        # pass in the default suite run. With more than one backend
        # configured, auth.login() can no longer infer one from `user.backend`
        # and raises ValueError unless it's passed explicitly.
        auth_login(request, self.user,
                  backend="django.contrib.auth.backends.ModelBackend")
        request.session.save()
        return request.session

    def test_verifying_sets_the_remember_my_browser_cookie(self):
        self._verify_and_get_cookie()  # asserts the cookie is present

    def test_trusted_browser_is_not_challenged_on_next_login(self):
        cookie_name, cookie_value = self._verify_and_get_cookie()
        session = self._login_with_cookies({cookie_name: cookie_value})
        self.assertTrue(session["mfa"]["verified"])
        self.assertEqual(session["mfa"]["method"], "remember_my_browser")

    def test_login_without_the_cookie_is_still_challenged(self):
        self._verify_and_get_cookie()
        session = self._login_with_cookies({})
        self.assertFalse(session["mfa"]["verified"])


class RememberMyBrowserOffByDefaultTests(TestCase):
    """MFA_REMEMBER_MY_BROWSER defaults to False -- the feature must stay
    strictly opt-in. No override_settings here on purpose."""

    def setUp(self):
        cache.clear()
        self.secret = "JBSWY3DPEHPK3PXP"
        self.user = User.objects.create_user("a@example.com", password="pw")
        Authenticator.objects.create(user=self.user, type="totp",
                                     data={"secret": self.secret})
        self.client = Client()

    def test_no_cookie_is_set_on_successful_verification(self):
        self.client.login(username="a@example.com", password="pw")
        response = self.client.post(
            reverse("mfa:verify_factor", args=["totp"]),
            {"code": totp_mod.TOTP(self.secret).now()})
        self.assertNotIn("RMB_%d" % self.user.pk, response.cookies)

    def test_every_login_is_still_challenged(self):
        self.client.login(username="a@example.com", password="pw")
        self.assertFalse(self.client.session["mfa"]["verified"])


class ExemptPathsSettingTests(TestCase):
    """Fix round 1, finding 2: MFA_EXEMPT_PATHS closes the logout trap --
    without it, a pending user with no way to complete their second factor
    (lost device, no recovery codes) can never reach even the host
    project's logout view, since it isn't in the registry-derived exempt
    set."""

    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        Authenticator.objects.create(user=self.user, type="totp")
        self.client = Client()
        self.client.login(username="a@example.com", password="pw")

    def test_listed_path_is_reachable_while_pending(self):
        path = reverse("mfa:security_settings")
        with override_settings(MFA_EXEMPT_PATHS=[path]):
            response = self.client.get(path)
        self.assertEqual(response.status_code, 200)

    def test_unlisted_path_still_redirects(self):
        with override_settings(MFA_EXEMPT_PATHS=["/some/other/logout/"]):
            response = self.client.get(reverse("mfa:security_settings"))
        self.assertEqual(response.status_code, 302)

    def test_default_is_empty_and_behaviour_is_unchanged(self):
        from django_mfa.conf import settings as mfa_settings
        self.assertEqual(mfa_settings.MFA_EXEMPT_PATHS, [])
        response = self.client.get(reverse("mfa:security_settings"))
        self.assertEqual(response.status_code, 302)


class NoFactorsCannotBeLockedOutTests(TestCase):
    """Final whole-branch review, finding 1 (CRITICAL): verify_factor used
    to stamp the session pending unconditionally, on any request that
    reached it -- including a plain GET from a user with NO enrolled
    factors at all. That user would then be redirected by MfaMiddleware to
    the picker (which renders zero options for them), with enroll_factor --
    the only page that could actually fix it -- itself blocked by the same
    middleware. Reachable by a plain, cross-site top-level navigation to
    /verify/<any registered type>/ (no CSRF token needed for a GET), this
    was a DoS against every not-yet-enrolled user.
    """

    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.client = Client()
        self.client.login(username="a@example.com", password="pw")

    def test_getting_verify_factor_does_not_stamp_a_factorless_user_pending(self):
        self.assertNotIn("mfa", self.client.session)
        response = self.client.get(reverse("mfa:verify_factor", args=["totp"]))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("mfa", self.client.session)

    def test_factorless_user_can_still_reach_enroll_after_visiting_verify(self):
        self.client.get(reverse("mfa:verify_factor", args=["totp"]))
        response = self.client.get(reverse("mfa:enroll_factor", args=["totp"]))
        self.assertEqual(response.status_code, 200)

    def test_factorless_user_can_still_reach_security_settings_after_visiting_verify(self):
        self.client.get(reverse("mfa:verify_factor", args=["totp"]))
        response = self.client.get(reverse("mfa:security_settings"))
        self.assertEqual(response.status_code, 200)

    def test_user_with_a_primary_factor_is_still_stamped_pending_on_a_stale_session(self):
        """Regression guard: the new no-factors guard must not weaken the
        existing behaviour for a user who DOES have a primary factor -- a
        stale/pre-existing session reaching this view directly (without
        having just gone through the login signal) must still be stamped
        pending, exactly as before this fix.
        """
        Authenticator.objects.create(user=self.user, type="totp")
        session = self.client.session
        session.pop("mfa", None)  # simulate a stale session
        session.save()

        self.client.get(reverse("mfa:verify_factor", args=["totp"]))
        self.assertFalse(self.client.session["mfa"]["verified"])


class ThirdPartyPrimaryFactorSignalTests(TestCase):
    """Final whole-branch review, finding 3: the login signal must decide
    whether to challenge a user purely from
    registry.primary_enabled_for(user) (Adapter.counts_as_primary_factor),
    not from a second, independent definition -- otherwise a third-party
    adapter that opts in (or out) via counts_as_primary_factor is silently
    ignored by the one place that actually enforces it.
    """

    def _register(self, adapter):
        from django_mfa.registry import registry

        registry.register(adapter)
        self.addCleanup(registry.unregister, adapter.type)

    def test_custom_adapter_opting_in_triggers_a_challenge(self):
        from django_mfa.registry import Adapter

        class CustomPrimaryAdapter(Adapter):
            type = "custom_primary"
            verbose_name = "Custom primary factor"
            counts_as_primary_factor = True

        self._register(CustomPrimaryAdapter())
        user = User.objects.create_user("c@example.com", password="pw")
        Authenticator.objects.create(user=user, type="custom_primary")

        client = Client()
        client.login(username="c@example.com", password="pw")
        self.assertFalse(client.session["mfa"]["verified"])

    def test_custom_adapter_opting_out_does_not_trigger_a_challenge(self):
        from django_mfa.registry import Adapter

        class CustomNonPrimaryAdapter(Adapter):
            type = "custom_nonprimary"
            verbose_name = "Custom non-primary factor"
            counts_as_primary_factor = False

        self._register(CustomNonPrimaryAdapter())
        user = User.objects.create_user("d@example.com", password="pw")
        Authenticator.objects.create(user=user, type="custom_nonprimary")

        client = Client()
        client.login(username="d@example.com", password="pw")
        self.assertNotIn("mfa", client.session)
