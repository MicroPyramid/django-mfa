from django.contrib.auth import login as auth_login
from django.contrib.auth.models import User
from django.contrib.sessions.backends.db import SessionStore
from django.core.cache import cache
from django.db import connection
from django.test import Client, RequestFactory, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from django_mfa import totp as totp_mod
from django_mfa.adapters.totp import generate_secret
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
        cookie_name = f"RMB_{self.user.pk}"
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
        self.assertNotIn(f"RMB_{self.user.pk}", response.cookies)

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

    def test_factorless_user_still_reaches_security_settings_after_verify(self):
        self.client.get(reverse("mfa:verify_factor", args=["totp"]))
        response = self.client.get(reverse("mfa:security_settings"))
        self.assertEqual(response.status_code, 200)

    def test_user_with_a_primary_factor_is_stamped_pending_on_stale_session(self):
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


class PendingUserCannotReachEnrollmentTests(TestCase):
    """A pending user must never reach an enroll page.

    enroll_factor() calls session.mark_verified() on success -- correct on
    its own terms, since enrolling proves possession. But it means a user who
    is mid-challenge could enroll a *fresh* TOTP with a secret of their own
    choosing and be marked verified without ever presenting the factor they
    already hold. The pending exempt set and the enrollment exempt set are
    therefore different sets, and unioning them is a vulnerability.

    This passes against the code as it was before the enrollment wall existed
    and must keep passing after.
    """

    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        Authenticator.objects.create(user=self.user, type="totp")
        self.client = Client()
        self.client.login(username="a@example.com", password="pw")

    def test_enroll_page_redirects_a_pending_user_to_verify(self):
        response = self.client.get(reverse("mfa:enroll_factor", args=["totp"]))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("mfa:verify"), response.url)

    def test_enrolling_cannot_be_posted_by_a_pending_user(self):
        secret = totp_mod.TOTP(generate_secret())
        response = self.client.post(
            reverse("mfa:enroll_factor", args=["totp"]),
            {"secret_key": secret.secret, "code": secret.now()})
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("mfa:verify"), response.url)
        self.assertFalse(self.client.session["mfa"]["verified"])


@override_settings(MFA_REQUIRED=True)
class EnrollmentWallTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.client = Client()
        self.client.login(username="a@example.com", password="pw")

    def test_a_required_user_with_no_factors_is_walled(self):
        response = self.client.get("/some/other/page/")
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("mfa:security_settings"), response.url)

    def test_the_wall_records_next_in_the_redirect_url(self):
        """Only that the parameter is *recorded*, not that anything reads it
        back -- neither enroll_factor nor security_settings look at `next`,
        so a user who enrolls here does not land back on this page. See the
        "What a required user sees" section of docs/enforcement.md.
        """
        response = self.client.get("/some/other/page/")
        # django.contrib.auth.views.redirect_to_login builds the querystring
        # via QueryDict.urlencode(safe="/"), which deliberately leaves "/"
        # unescaped -- so this is "/some/other/page/", not the %2F-escaped
        # form. Confirmed against the real redirect: assert on the decoded
        # form actually produced rather than a hand-guessed encoding.
        self.assertIn("next=/some/other/page/", response.url)

    def test_security_settings_itself_is_reachable(self):
        response = self.client.get(reverse("mfa:security_settings"))
        self.assertEqual(response.status_code, 200)

    def test_enroll_pages_are_reachable(self):
        response = self.client.get(reverse("mfa:enroll_factor", args=["totp"]))
        self.assertEqual(response.status_code, 200)

    def test_recovery_codes_page_is_reachable(self):
        response = self.client.get(reverse("mfa:recovery_codes"))
        self.assertEqual(response.status_code, 200)

    @override_settings(MFA_EXEMPT_PATHS=["/logout/"])
    def test_exempt_paths_apply_to_the_wall_too(self):
        """Without this a required user who cannot enroll -- no phone, no
        security key -- is trapped with no way even to log out."""
        response = self.client.get("/logout/")
        self.assertNotEqual(response.status_code, 302)

    def test_recovery_codes_alone_do_not_satisfy_the_requirement(self):
        Authenticator.objects.create(user=self.user, type="recovery_codes")
        response = self.client.get("/some/other/page/")
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("mfa:security_settings"), response.url)

    def test_a_primary_factor_releases_the_wall(self):
        Authenticator.objects.create(user=self.user, type="totp")
        session = self.client.session
        session["mfa"] = {"verified": True, "method": "totp", "at": 0}
        session.save()
        response = self.client.get("/some/other/page/")
        self.assertEqual(response.status_code, 404)  # walled off -> not found

    def test_the_security_page_explains_why(self):
        response = self.client.get(reverse("mfa:security_settings"))
        self.assertTrue(response.context["mfa_enrollment_required"])


class WallIsOffByDefaultTests(TestCase):
    def test_an_unrequired_user_with_no_factors_is_untouched(self):
        User.objects.create_user("b@example.com", password="pw")
        client = Client()
        client.login(username="b@example.com", password="pw")
        response = client.get("/some/other/page/")
        self.assertEqual(response.status_code, 404)


class MfaRequiredQueryCostTests(TestCase):
    """Important 4, end-to-end: the reviewer measured 2 queries for a
    fully-enrolled, verified user requesting an unrelated page with
    MFA_REQUIRED=False, and 5 with it on -- +3, one .exists() query per
    registered adapter (totp, webauthn, recovery_codes here), from
    MfaMiddleware's second rung calling registry.primary_enabled_for() where
    only the yes/no answer was ever needed.

    registry.has_primary_factor() (Important 4's fix) must bring that delta
    down to +1 -- has_primary_factor's own single .exists() query -- no
    matter how many adapters are registered, since MFA_REQUIRED=True is the
    only thing that makes the middleware's second rung run at all.
    """

    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        for factor_type in ("totp", "webauthn", "recovery_codes"):
            Authenticator.objects.create(user=self.user, type=factor_type)
        self.client = Client()
        self.client.login(username="a@example.com", password="pw")
        session = self.client.session
        session["mfa"] = {"verified": True, "method": "totp", "at": 0}
        session.save()

    def test_requiring_mfa_costs_exactly_one_extra_query(self):
        with override_settings(MFA_REQUIRED=False):
            with CaptureQueriesContext(connection) as unrequired:
                response = self.client.get("/some/other/page/")
            self.assertEqual(response.status_code, 404)

        with override_settings(MFA_REQUIRED=True):
            with CaptureQueriesContext(connection) as required:
                response = self.client.get("/some/other/page/")
            self.assertEqual(response.status_code, 404)

        delta = len(required.captured_queries) - len(unrequired.captured_queries)
        self.assertEqual(
            delta, 1,
            "MFA_REQUIRED=True should cost exactly one extra query over "
            "MFA_REQUIRED=False (has_primary_factor's own .exists()), not "
            "one per registered adapter. Queries when required: "
            f"{[q['sql'] for q in required.captured_queries]}")
