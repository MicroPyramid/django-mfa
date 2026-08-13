from django.conf import settings as django_settings
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.test import Client, TestCase, override_settings
from django.urls import include, path, reverse
from django.views.generic import View

from django_mfa.decorators import MfaRequiredMixin, mfa_required
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
