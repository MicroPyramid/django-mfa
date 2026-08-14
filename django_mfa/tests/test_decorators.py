import time

from django.conf import settings as django_settings
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import include, path, reverse
from django.views.generic import View

from django_mfa.decorators import (
    PENDING,
    UNENROLLED,
    MfaRequiredMixin,
    enforcement_state,
    mfa_required,
)
from django_mfa.models import Authenticator


@mfa_required
def protected(request):
    return HttpResponse("protected")


class ProtectedView(MfaRequiredMixin, View):
    def get(self, request):
        return HttpResponse("protected cbv")


urlpatterns = [
    path("protected/", protected, name="protected"),
    path("protected-cbv/", ProtectedView.as_view(), name="protected_cbv"),
    path("", include("django_mfa.urls")),
]

# MfaMiddleware is also installed (see test_runner.py's MIDDLEWARE) and
# would redirect a pending user itself, before the view -- and therefore
# before mfa_required/MfaRequiredMixin's own _enforce() -- ever runs, since
# neither /protected/ nor /protected-cbv/ is in its exempt_paths(). The
# pending-rung tests below need that middleware out of the stack, or they
# cannot tell _enforce()'s own pending check apart from the middleware's.
_MIDDLEWARE_WITHOUT_MFA = [
    m for m in django_settings.MIDDLEWARE
    if m != "django_mfa.middleware.MfaMiddleware"
]


@override_settings(ROOT_URLCONF="django_mfa.tests.test_decorators",
                   LOGIN_URL="/login/")
class MfaRequiredDecoratorTests(TestCase):
    url_name = "protected"

    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.client = Client()

    def url(self):
        return reverse(self.url_name)

    def test_anonymous_goes_to_the_login_page(self):
        response = self.client.get(self.url())
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)

    def test_pending_user_goes_to_the_verify_picker(self):
        Authenticator.objects.create(user=self.user, type="totp")
        self.client.login(username="a@example.com", password="pw")
        response = self.client.get(self.url())
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("mfa:verify"), response.url)

    def test_user_with_no_factor_goes_to_the_security_page(self):
        self.client.login(username="a@example.com", password="pw")
        response = self.client.get(self.url())
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("mfa:security_settings"), response.url)

    def test_recovery_codes_alone_are_not_enough(self):
        Authenticator.objects.create(user=self.user, type="recovery_codes")
        self.client.login(username="a@example.com", password="pw")
        response = self.client.get(self.url())
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("mfa:security_settings"), response.url)

    def test_verified_user_reaches_the_view(self):
        Authenticator.objects.create(user=self.user, type="totp")
        self.client.login(username="a@example.com", password="pw")
        session = self.client.session
        session["mfa"] = {"verified": True, "method": "totp", "at": 0}
        session.save()
        response = self.client.get(self.url())
        self.assertEqual(response.status_code, 200)

    def test_next_is_preserved(self):
        self.client.login(username="a@example.com", password="pw")
        response = self.client.get(self.url())
        self.assertIn("next=", response.url)

    def test_the_decorator_keeps_the_view_name(self):
        self.assertEqual(protected.__name__, "protected")


@override_settings(ROOT_URLCONF="django_mfa.tests.test_decorators",
                   LOGIN_URL="/login/")
class MfaRequiredMixinTests(MfaRequiredDecoratorTests):
    """The mixin must behave identically to the decorator, so it reruns the
    whole case list against the class-based view."""

    url_name = "protected_cbv"

    def test_the_decorator_keeps_the_view_name(self):
        self.skipTest("not applicable to the mixin")


@override_settings(ROOT_URLCONF="django_mfa.tests.test_decorators",
                   LOGIN_URL="/login/", MIDDLEWARE=_MIDDLEWARE_WITHOUT_MFA)
class PendingRungIsolatedFromMiddlewareTests(TestCase):
    """_enforce()'s pending rung, proven independent of MfaMiddleware.

    MfaRequiredDecoratorTests.test_pending_user_goes_to_the_verify_picker
    runs with MfaMiddleware still installed, so it cannot tell _enforce()'s
    own pending check apart from the middleware's identical one: the
    middleware redirects first and the view is never reached. Removing
    MfaMiddleware from MIDDLEWARE for this class means the redirect can
    only come from the decorator/mixin itself.
    """

    url_name = "protected"

    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.client = Client()

    def url(self):
        return reverse(self.url_name)

    def test_pending_user_goes_to_the_verify_picker(self):
        Authenticator.objects.create(user=self.user, type="totp")
        self.client.login(username="a@example.com", password="pw")
        response = self.client.get(self.url())
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("mfa:verify"), response.url)


@override_settings(ROOT_URLCONF="django_mfa.tests.test_decorators",
                   LOGIN_URL="/login/", MIDDLEWARE=_MIDDLEWARE_WITHOUT_MFA)
class MixinPendingRungIsolatedFromMiddlewareTests(
        PendingRungIsolatedFromMiddlewareTests):
    """Same proof, against the mixin's class-based view."""

    url_name = "protected_cbv"


class UnchallengedSessionTests(TestCase):
    """A session that was never stamped at all is not "verified".

    `session.is_pending()` means "stamped, not yet passed", so it is False for
    a session with no `mfa` key -- and without a rung of its own, such a
    request falls through enforcement_state() to `None` and is treated exactly
    as one that passed a challenge.

    A browser reaches that state only by missing signals.stamp_pending_
    verification: force_login() in a host project's own tests, or a session
    that predates the app being installed. A cookie-less API client is in it
    on every single request, which is what makes this load-bearing rather than
    defensive -- see django_mfa/api/tokens.py.
    """

    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.factory = RequestFactory()

    def _request(self, session=None):
        request = self.factory.get("/somewhere/")
        request.user = self.user
        request.session = {} if session is None else session
        return request

    def test_a_user_with_a_factor_and_no_stamp_is_pending(self):
        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP, data={})
        self.assertEqual(enforcement_state(self._request()), PENDING)

    def test_a_user_with_no_factor_still_falls_to_unenrolled(self):
        """The rung must not shadow the enrollment rung, or a factorless user
        is redirected to verify -- a page with nothing to offer them -- instead
        of to the security page where they can fix it."""
        self.assertEqual(enforcement_state(self._request()), UNENROLLED)

    def test_a_factorless_user_is_let_through_when_enrollment_is_waived(self):
        """allow_unenrolled=True says "unenrolled is fine here", which is what
        lets the built-in enroll views be reached. It must not also be read as
        "unverified is fine here"."""
        self.assertIsNone(
            enforcement_state(self._request(), require_primary_factor=False))

    def test_a_user_with_a_factor_is_pending_even_when_enrollment_is_waived(self):
        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP, data={})
        self.assertEqual(
            enforcement_state(self._request(), require_primary_factor=False),
            PENDING)

    def test_a_verified_session_still_passes(self):
        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP, data={})
        verified = {"mfa": {"verified": True, "method": "totp",
                            "at": int(time.time())}}
        self.assertIsNone(enforcement_state(self._request(verified)))

    def test_a_stamped_pending_session_is_unchanged(self):
        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP, data={})
        pending = {"mfa": {"verified": False, "method": None, "at": None}}
        self.assertEqual(enforcement_state(self._request(pending)), PENDING)

    def test_recovery_codes_alone_do_not_trigger_it(self):
        """has_primary_factor(), so an account holding only recovery codes is
        still UNENROLLED rather than being challenged with the one factor it
        must never be allowed to rely on."""
        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.RECOVERY_CODES, data={})
        self.assertEqual(enforcement_state(self._request()), UNENROLLED)
