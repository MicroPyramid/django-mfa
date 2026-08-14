"""The JSON API, with the emphasis on what it must refuse.

The API is a second way into the same factors. Its whole risk is being a
*weaker* way in -- an endpoint that skips a gate the HTML view applies, or
distinguishes two failures the HTML view deliberately renders alike. Both
keep working when broken, and neither is visible from the outside, so most
of what is here is about refusals rather than happy paths.
"""

import json
import time

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse

from django_mfa.adapters.totp import generate_secret
from django_mfa.api import urls as api_urls
from django_mfa.crypto import encrypt
from django_mfa.middleware import MfaMiddleware
from django_mfa.models import Authenticator
from django_mfa.totp import TOTP

API_URLS = "django_mfa.tests.support.api_urls"


def code_for(secret):
    return TOTP(secret).now()


@override_settings(ROOT_URLCONF=API_URLS)
class ApiTestCase(TestCase):
    def setUp(self):
        # The rate limiter is cache-backed, and Django's TestCase rolls back
        # the database between tests but not the cache. Without this, one
        # test's failed attempts spend the next test's budget and a correct
        # code comes back rejected -- an inter-test dependency that shows up
        # as a failure in whichever test happens to run second.
        cache.clear()
        self.secret = generate_secret()
        self.user = User.objects.create_user("ada", password="pw")
        self.client.force_login(self.user)

    def enroll_totp(self):
        return Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP,
            data={"secret": encrypt(self.secret)})

    def url(self, name, **kwargs):
        return reverse(f"mfa_api:{name}", kwargs=kwargs or None)

    def post(self, name, body=None, **kwargs):
        return self.client.post(
            self.url(name, **kwargs), data=json.dumps(body or {}),
            content_type="application/json")

    def body(self, response):
        return json.loads(response.content)

    def error_code(self, response):
        return self.body(response)["error"]["code"]

    def set_session_mfa(self, **state):
        store = self.client.session
        store["mfa"] = {"verified": False, "method": None, "at": None} | state
        store.save()


class AuthenticationTests(ApiTestCase):
    def test_anonymous_gets_401(self):
        self.client.logout()
        response = self.client.get(self.url("state"))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.error_code(response), "unauthenticated")

    def test_wrong_method_is_405(self):
        response = self.client.get(self.url("recovery_codes"))
        self.assertEqual(response.status_code, 405)
        self.assertEqual(self.error_code(response), "method_not_allowed")

    def test_malformed_body_is_rejected(self):
        self.enroll_totp()
        response = self.client.post(
            self.url("verify_complete", factor_type="totp"),
            data="[1, 2, 3]", content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.error_code(response), "malformed_body")

    @override_settings(MFA_API_AUTHENTICATION="django_mfa.tests.test_api.as_ada")
    def test_custom_resolver_identifies_the_user(self):
        """And request.user follows it.

        The adapters create Authenticator rows against request.user, so a
        resolver that named a different user than the session would enroll
        onto the wrong account if the view did not reassign it.
        """
        self.client.logout()
        response = self.client.get(self.url("state"))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.body(response)["can_enroll"])

    @override_settings(MFA_API_AUTHENTICATION="django_mfa.tests.test_api.nobody")
    def test_custom_resolver_returning_none_is_401(self):
        response = self.client.get(self.url("state"))
        self.assertEqual(response.status_code, 401)


def as_ada(request):
    return User.objects.get(username="ada")


def nobody(request):
    return None


class StateTests(ApiTestCase):
    def test_state_is_reachable_while_pending(self):
        """A client cannot draw a challenge screen it is not allowed to ask
        about."""
        self.enroll_totp()
        self.set_session_mfa(verified=False)
        response = self.client.get(self.url("state"))
        self.assertEqual(response.status_code, 200)
        body = self.body(response)
        self.assertTrue(body["pending"])
        self.assertFalse(body["verified"])
        self.assertEqual([a["type"] for a in body["can_verify_with"]], ["totp"])

    def test_state_never_exposes_authenticator_data(self):
        """The TOTP secret, the recovery-code hashes and the WebAuthn
        credential all live in `data`. None of it may leave the server."""
        self.enroll_totp()
        response = self.client.get(self.url("state"))
        raw = response.content.decode()
        self.assertNotIn("data", self.body(response)["authenticators"][0])
        self.assertNotIn(self.secret, raw)
        self.assertNotIn(encrypt(self.secret), raw)


class PendingSessionTests(ApiTestCase):
    """The enroll/verify split, which is the API's sharpest edge.

    Enrolling marks a session verified. So a *pending* user who could reach
    an enroll endpoint could satisfy their own challenge with a brand new
    factor of their choosing, without ever presenting the one they hold --
    a complete bypass of the second factor for anyone holding only the
    password. The HTML views keep enroll out of the pending-exempt set for
    exactly this reason; the API must not be the way around it.
    """

    def test_enroll_begin_is_refused_while_pending(self):
        self.enroll_totp()
        self.set_session_mfa(verified=False)
        response = self.post("enroll_begin", factor_type="webauthn")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.error_code(response), "verification_required")

    def test_enroll_complete_is_refused_while_pending(self):
        self.enroll_totp()
        self.set_session_mfa(verified=False)
        fresh = generate_secret()
        response = self.post("enroll_complete", factor_type="totp",
                             body={"secret_key": fresh,
                                   "code": code_for(fresh)})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.error_code(response), "verification_required")
        self.assertFalse(self.client.session["mfa"]["verified"])

    def test_recovery_codes_are_refused_while_pending(self):
        self.enroll_totp()
        self.set_session_mfa(verified=False)
        response = self.post("recovery_codes")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.error_code(response), "verification_required")

    def test_removal_is_refused_while_pending(self):
        authenticator = self.enroll_totp()
        self.set_session_mfa(verified=False)
        response = self.client.delete(
            self.url("remove_factor", pk=authenticator.pk))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(
            Authenticator.objects.filter(pk=authenticator.pk).exists())

    def test_verify_is_reachable_while_pending(self):
        """The one thing that must work -- it is how a session stops being
        pending."""
        self.enroll_totp()
        self.set_session_mfa(verified=False)
        response = self.post("verify_complete", factor_type="totp",
                             body={"code": code_for(self.secret)})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.body(response)["verified"])


class VerifyTests(ApiTestCase):
    def setUp(self):
        super().setUp()
        self.enroll_totp()
        self.set_session_mfa(verified=False)

    def test_correct_code_verifies_the_session(self):
        response = self.post("verify_complete", factor_type="totp",
                             body={"code": code_for(self.secret)})
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(self.body(response)["verified_at"])
        self.assertTrue(self.client.session["mfa"]["verified"])

    def test_unknown_factor_is_404(self):
        response = self.post("verify_complete", factor_type="carrier-pigeon")
        self.assertEqual(response.status_code, 404)

    def test_every_failure_looks_identical(self):
        """A wrong code, a missing field and a rate-limited attempt must be
        indistinguishable. Any difference is an oracle -- and a
        distinguishable lockout tells an attacker precisely when to pause.
        """
        bodies = []
        for attempt in ({"code": "000000"}, {}, {"code": "not-a-code"}):
            response = self.post("verify_complete", factor_type="totp",
                                 body=attempt)
            self.assertEqual(response.status_code, 400)
            bodies.append(response.content)

        # MFA_VERIFY_RATE_LIMIT defaults to 5/5m, so this one is refused
        # without being evaluated at all.
        for _ in range(5):
            self.post("verify_complete", factor_type="totp",
                      body={"code": "000000"})
        locked = self.post("verify_complete", factor_type="totp",
                           body={"code": code_for(self.secret)})
        self.assertEqual(locked.status_code, 400)
        bodies.append(locked.content)

        self.assertEqual(len(set(bodies)), 1, "failure responses differ")

    def test_a_malformed_attempt_still_spends_from_the_budget(self):
        """Otherwise an attacker gets unlimited attempts by malforming
        them."""
        for _ in range(5):
            self.post("verify_complete", factor_type="totp", body={})
        response = self.post("verify_complete", factor_type="totp",
                             body={"code": code_for(self.secret)})
        self.assertEqual(response.status_code, 400,
                         "the correct code was accepted despite the budget "
                         "being spent, so malformed attempts were free")


class EnrollTests(ApiTestCase):
    def setUp(self):
        super().setUp()
        self.set_session_mfa(verified=True, method="totp", at=int(time.time()))

    def test_enroll_round_trip(self):
        begin = self.post("enroll_begin", factor_type="totp")
        self.assertEqual(begin.status_code, 200)
        secret = self.body(begin)["secret_key"]

        response = self.post("enroll_complete", factor_type="totp",
                             body={"secret_key": secret,
                                   "code": code_for(secret)})
        self.assertEqual(response.status_code, 201)
        body = self.body(response)
        self.assertEqual(body["authenticator"]["type"], "totp")
        self.assertTrue(body["recovery_codes_pending"])
        self.assertNotIn("data", body["authenticator"])
        self.assertTrue(Authenticator.objects.filter(
            user=self.user, type="totp").exists())

    def test_wrong_code_creates_nothing(self):
        secret = self.body(self.post("enroll_begin",
                                     factor_type="totp"))["secret_key"]
        response = self.post("enroll_complete", factor_type="totp",
                             body={"secret_key": secret, "code": "000000"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.error_code(response), "invalid")
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())

    def test_recovery_codes_are_not_enrollable(self):
        """They are generated, not enrolled -- the same 404 the HTML view
        gives a hand-typed URL."""
        self.assertEqual(
            self.post("enroll_begin", factor_type="recovery_codes").status_code,
            404)


class StepUpTests(ApiTestCase):
    """MFA_STEPUP_MAX_AGE applies here exactly as it does to the HTML views."""

    def setUp(self):
        super().setUp()
        self.enroll_totp()

    def test_stale_session_cannot_enroll(self):
        self.set_session_mfa(verified=True, method="totp",
                             at=int(time.time()) - 3600)
        response = self.post("enroll_begin", factor_type="webauthn")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.error_code(response), "stepup_required")

    def test_stale_session_cannot_remove_a_factor(self):
        row = Authenticator.objects.get(user=self.user, type="totp")
        self.set_session_mfa(verified=True, method="totp",
                             at=int(time.time()) - 3600)
        response = self.client.delete(self.url("remove_factor", pk=row.pk))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.error_code(response), "stepup_required")
        self.assertTrue(Authenticator.objects.filter(pk=row.pk).exists())

    def test_fresh_session_may_enroll(self):
        self.set_session_mfa(verified=True, method="totp", at=int(time.time()))
        self.assertEqual(
            self.post("enroll_begin", factor_type="webauthn").status_code, 200)

    @override_settings(MFA_STEPUP_MAX_AGE=None)
    def test_step_up_can_be_switched_off(self):
        self.set_session_mfa(verified=True, method="totp",
                             at=int(time.time()) - 3600)
        self.assertEqual(
            self.post("enroll_begin", factor_type="webauthn").status_code, 200)


class RemovalTests(ApiTestCase):
    def setUp(self):
        super().setUp()
        self.set_session_mfa(verified=True, method="totp", at=int(time.time()))

    def test_removal_deletes_the_row(self):
        row = self.enroll_totp()
        response = self.client.delete(self.url("remove_factor", pk=row.pk))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Authenticator.objects.filter(pk=row.pk).exists())

    def test_another_users_factor_is_404_not_403(self):
        """404, so the endpoint is not a probe for which ids exist."""
        other = User.objects.create_user("bob", password="pw")
        row = Authenticator.objects.create(
            user=other, type=Authenticator.Type.TOTP,
            data={"secret": encrypt(generate_secret())})
        self.enroll_totp()
        response = self.client.delete(self.url("remove_factor", pk=row.pk))
        self.assertEqual(response.status_code, 404)
        self.assertTrue(Authenticator.objects.filter(pk=row.pk).exists())

    def test_unparseable_pk_is_404_not_500(self):
        self.enroll_totp()
        self.assertEqual(
            self.client.delete(self.url("remove_factor", pk="nonsense")
                               ).status_code, 404)

    @override_settings(MFA_OWNED_BY_ENTERPRISE=True)
    def test_enterprise_owned_key_cannot_be_removed(self):
        self.enroll_totp()
        row = Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.WEBAUTHN, data={})
        response = self.client.delete(self.url("remove_factor", pk=row.pk))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.error_code(response), "managed_by_enterprise")
        self.assertTrue(Authenticator.objects.filter(pk=row.pk).exists())


class RecoveryCodeTests(ApiTestCase):
    def setUp(self):
        super().setUp()
        self.enroll_totp()
        self.set_session_mfa(verified=True, method="totp", at=int(time.time()))

    def test_codes_are_returned_once(self):
        first = self.post("recovery_codes")
        self.assertEqual(first.status_code, 201)
        codes = self.body(first)["codes"]
        self.assertEqual(len(codes), 10)

        second = self.post("recovery_codes")
        self.assertEqual(second.status_code, 200)
        self.assertIsNone(self.body(second)["codes"],
                          "plaintext is not stored, so there is nothing "
                          "honest to return a second time")
        self.assertEqual(self.body(second)["remaining"], 10)

    def test_codes_are_not_recoverable_from_the_state_endpoint(self):
        codes = self.body(self.post("recovery_codes"))["codes"]
        raw = self.client.get(self.url("state")).content.decode()
        for code in codes:
            self.assertNotIn(code, raw)


class CsrfTests(ApiTestCase):
    """A session-authenticated JSON endpoint is as forgeable as a form post
    without CSRF protection."""

    def setUp(self):
        super().setUp()
        self.client = self.client_class(enforce_csrf_checks=True)
        self.client.force_login(self.user)
        self.set_session_mfa(verified=True, method="totp", at=int(time.time()))

    def test_post_without_a_token_is_refused(self):
        response = self.client.post(
            self.url("enroll_begin", factor_type="totp"),
            data="{}", content_type="application/json")
        self.assertEqual(response.status_code, 403)

    def test_get_needs_no_token(self):
        self.assertEqual(self.client.get(self.url("state")).status_code, 200)


class NoRedirectsTests(ApiTestCase):
    """The middleware never answers an API request with a redirect.

    A 302 to an HTML page is not something a JSON client can act on, and
    following it yields a 200 full of markup where JSON was expected --
    which is worse, because it looks like success.
    """

    def test_a_pending_session_gets_json_not_a_redirect(self):
        self.enroll_totp()
        self.set_session_mfa(verified=False)
        for response in (
            self.post("enroll_begin", factor_type="totp"),
            self.post("recovery_codes"),
            self.client.get(self.url("state")),
        ):
            self.assertNotEqual(response.status_code, 302)
            self.assertEqual(response["Content-Type"], "application/json")

    @override_settings(MFA_REQUIRED=True)
    def test_a_walled_unenrolled_user_gets_json_not_a_redirect(self):
        response = self.client.get(self.url("state"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertFalse(self.body(response)["has_primary_factor"])

    def test_html_pages_still_redirect(self):
        """The exemption is scoped to the API namespace, not switched on
        globally by mounting it."""
        self.enroll_totp()
        self.set_session_mfa(verified=False)
        response = self.client.get(reverse("mfa:security_settings"))
        self.assertEqual(response.status_code, 302)


class EveryEndpointIsGatedTests(ApiTestCase):
    """Enumerated, so a new endpoint cannot quietly arrive ungated.

    Since the middleware no longer stops a pending user from reaching these
    URLs, each view's own gate is the only thing left -- and an endpoint
    added without one would be a complete second-factor bypass for anyone
    holding just a password. This walks the URLconf rather than a list, so
    the guard covers routes that did not exist when it was written.
    """

    #: Reachable while pending, and each for a reason. state: a client
    #: cannot draw a challenge screen it may not ask about. verify_*: they
    #: are how a session stops being pending. passkey_*: anonymous by
    #: definition -- they are a login.
    PENDING_ALLOWED = {"state", "verify_begin", "verify_complete",
                       "passkey_begin", "passkey_complete"}

    def test_every_endpoint_refuses_a_pending_session(self):
        self.enroll_totp()
        self.set_session_mfa(verified=False)

        checked = set()
        for pattern in api_urls.api_patterns[0]:
            name = pattern.name
            if name in self.PENDING_ALLOWED:
                continue
            checked.add(name)
            route = str(pattern.pattern)
            kwargs = {}
            if "factor_type" in route:
                kwargs["factor_type"] = "totp"
            if "pk" in route:
                kwargs["pk"] = str(self.user.pk)
            url = self.url(name, **kwargs)
            for method in ("get", "post", "delete"):
                response = getattr(self.client, method)(url)
                with self.subTest(endpoint=name, method=method):
                    self.assertIn(response.status_code, (403, 405),
                                  f"{method.upper()} {url} answered "
                                  f"{response.status_code} to a pending "
                                  f"session; it must refuse or reject the "
                                  f"method")
                    if response.status_code == 403:
                        self.assertEqual(self.error_code(response),
                                         "verification_required")
        self.assertTrue(checked, "no endpoints were checked at all")


class ApiNotMountedTests(TestCase):
    """The API is opt-in, so most installs never mount it.

    MfaMiddleware reverses `mfa_api:` names to build its exempt sets. Under
    the suite's default ROOT_URLCONF those names do not resolve, which must
    be an ordinary "nothing to add" rather than a NoReverseMatch on every
    single request.
    """

    def test_exempt_sets_build_without_the_api(self):
        middleware = MfaMiddleware(lambda request: None)
        self.assertTrue(middleware.exempt_paths())
        self.assertTrue(middleware.enrollment_exempt_paths())

    def test_an_ordinary_request_still_works(self):
        user = User.objects.create_user("ada", password="pw")
        self.client.force_login(user)
        self.assertEqual(
            self.client.get(reverse("mfa:security_settings")).status_code, 200)
