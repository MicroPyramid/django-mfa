import time

from django.contrib.auth.models import User
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.views import View

from django_mfa import session
from django_mfa.adapters.totp import generate_secret
from django_mfa.checks import check_stepup_max_age
from django_mfa.crypto import encrypt
from django_mfa.decorators import MfaRecentRequiredMixin, mfa_recent_required
from django_mfa.models import Authenticator


class FreshnessTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def _request(self, mfa_state):
        request = self.factory.get("/")
        request.session = {}
        if mfa_state is not None:
            request.session["mfa"] = mfa_state
        return request

    def test_no_mfa_state_is_not_fresh(self):
        self.assertFalse(session.is_fresh(self._request(None), 300))

    def test_pending_session_is_not_fresh(self):
        request = self._request({"verified": False, "method": None, "at": None})
        self.assertFalse(session.is_fresh(request, 300))

    def test_verified_without_at_is_stale(self):
        # A session verified by 4.1.0 or earlier. Stale is the safe direction.
        request = self._request({"verified": True, "method": "totp", "at": None})
        self.assertFalse(session.is_fresh(request, 300))

    def test_recently_verified_is_fresh(self):
        request = self._request(
            {"verified": True, "method": "totp", "at": int(time.time())})
        self.assertTrue(session.is_fresh(request, 300))

    def test_old_verification_is_stale(self):
        request = self._request(
            {"verified": True, "method": "totp", "at": int(time.time()) - 301})
        self.assertFalse(session.is_fresh(request, 300))

    def test_exactly_at_the_boundary_is_fresh(self):
        request = self._request(
            {"verified": True, "method": "totp", "at": int(time.time()) - 300})
        self.assertTrue(session.is_fresh(request, 300))

    def test_verified_at_returns_the_stamp(self):
        stamp = int(time.time())
        request = self._request({"verified": True, "method": "totp", "at": stamp})
        self.assertEqual(session.verified_at(request), stamp)

    def test_verified_at_is_none_without_state(self):
        self.assertIsNone(session.verified_at(self._request(None)))


class StepUpCheckTests(TestCase):
    def test_default_passes(self):
        self.assertEqual(check_stepup_max_age(None), [])

    @override_settings(MFA_STEPUP_MAX_AGE=None)
    def test_none_passes(self):
        self.assertEqual(check_stepup_max_age(None), [])

    @override_settings(MFA_STEPUP_MAX_AGE=0)
    def test_zero_is_refused(self):
        errors = check_stepup_max_age(None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E005"])

    @override_settings(MFA_STEPUP_MAX_AGE=-1)
    def test_negative_is_refused(self):
        self.assertEqual([e.id for e in check_stepup_max_age(None)],
                         ["django_mfa.E005"])

    @override_settings(MFA_STEPUP_MAX_AGE=True)
    def test_bool_is_refused(self):
        # bool is a subclass of int; True would silently mean "1 second".
        self.assertEqual([e.id for e in check_stepup_max_age(None)],
                         ["django_mfa.E005"])

    @override_settings(MFA_STEPUP_MAX_AGE="300")
    def test_string_is_refused(self):
        self.assertEqual([e.id for e in check_stepup_max_age(None)],
                         ["django_mfa.E005"])


@mfa_recent_required()
def gated_view(request):
    return HttpResponse("ok")


@mfa_recent_required
def bare_gated_view(request):
    return HttpResponse("ok")


@mfa_recent_required(max_age=60)
def tight_gated_view(request):
    return HttpResponse("ok")


@mfa_recent_required(allow_unenrolled=True)
def permissive_gated_view(request):
    return HttpResponse("ok")


class GatedCBV(MfaRecentRequiredMixin, View):
    def get(self, request):
        return HttpResponse("ok")


class PermissiveGatedCBV(MfaRecentRequiredMixin, View):
    mfa_allow_unenrolled = True

    def get(self, request):
        return HttpResponse("ok")


class GateTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user("a@example.com", password="pw")

    def _request(self, path="/thing/", method="get", at=None, verified=True,
                 user=None):
        request = getattr(self.factory, method)(path)
        request.user = user if user is not None else self.user
        request.session = {}
        if verified is not None:
            request.session["mfa"] = {
                "verified": verified, "method": "totp", "at": at}
        return request

    def _give_totp(self):
        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP,
            data={"secret": encrypt(generate_secret())})

    def test_fresh_session_passes(self):
        self._give_totp()
        response = gated_view(self._request(at=int(time.time())))
        self.assertEqual(response.status_code, 200)

    def test_stale_session_redirects_to_verify(self):
        self._give_totp()
        response = gated_view(self._request(at=int(time.time()) - 3600))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/verify/", response["Location"])
        # redirect_to_login builds the querystring via
        # QueryDict.urlencode(safe="/"), which deliberately leaves "/"
        # unescaped -- see the matching comment in test_enforcement.py.
        self.assertIn("next=/thing/", response["Location"])

    def test_user_without_primary_factor_passes_while_stale(self):
        # LOAD-BEARING: this is the first-enrolment path. A user with nothing
        # to re-verify must never be gated when the view opts in via
        # allow_unenrolled=True (as the built-in enrollment views do), or
        # they are locked out of the only pages that could give them a
        # factor. Uses permissive_gated_view, not gated_view: the default
        # (allow_unenrolled=False) is exercised separately below and is
        # strict, not permissive.
        response = permissive_gated_view(self._request(at=None))
        self.assertEqual(response.status_code, 200)

    def test_recovery_codes_alone_do_not_trigger_the_gate(self):
        # Recovery codes set counts_as_primary_factor = False, so a user
        # holding only those has no primary factor and, under
        # allow_unenrolled=True, must pass through.
        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.RECOVERY_CODES,
            data={"codes": [], "used": []})
        response = permissive_gated_view(self._request(at=None))
        self.assertEqual(response.status_code, 200)

    def test_factorless_user_is_gated_by_default(self):
        # allow_unenrolled defaults to False: mfa_recent_required is then
        # strictly stronger than mfa_required, so a factorless user gets
        # exactly the security_settings redirect mfa_required would give,
        # never reaching the freshness rung at all.
        response = gated_view(self._request(at=None))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/security/", response["Location"])
        self.assertIn("next=/thing/", response["Location"])

    def test_factorless_user_passes_with_allow_unenrolled(self):
        response = permissive_gated_view(self._request(at=None))
        self.assertEqual(response.status_code, 200)

    def test_unsafe_method_redirects_to_security_settings_not_the_post_url(self):
        # manage_factors is POST-only and 405s on GET; bouncing the POST URL
        # back through the verify flow would land the user on that 405.
        self._give_totp()
        response = gated_view(self._request(method="post", at=0))
        self.assertEqual(response.status_code, 302)
        self.assertIn("next=/security/", response["Location"])

    def test_explicit_next_url_overrides_for_unsafe_methods(self):
        self._give_totp()

        @mfa_recent_required(next_url="/elsewhere/")
        def view(request):
            return HttpResponse("ok")

        response = view(self._request(method="post", at=0))
        self.assertIn("next=/elsewhere/", response["Location"])

    @override_settings(MFA_STEPUP_MAX_AGE=None)
    def test_setting_none_disables_the_gate(self):
        self._give_totp()
        response = gated_view(self._request(at=0))
        self.assertEqual(response.status_code, 200)

    def test_explicit_max_age_overrides_the_setting(self):
        self._give_totp()
        request = self._request(at=int(time.time()) - 120)
        self.assertEqual(gated_view(request).status_code, 200)       # 300s window
        self.assertEqual(tight_gated_view(request).status_code, 302)  # 60s window

    def test_bare_and_called_forms_behave_identically(self):
        self._give_totp()
        stale = self._request(at=0)
        self.assertEqual(bare_gated_view(stale).status_code, 302)
        self.assertEqual(gated_view(stale).status_code, 302)

    def test_pending_session_is_handled_by_the_earlier_rung(self):
        self._give_totp()
        response = gated_view(self._request(at=None, verified=False))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/verify/", response["Location"])

    def test_mixin_matches_the_decorator(self):
        self._give_totp()
        view = GatedCBV.as_view()
        self.assertEqual(view(self._request(at=int(time.time()))).status_code, 200)
        self.assertEqual(view(self._request(at=0)).status_code, 302)

    def test_mixin_factorless_user_is_gated_by_default(self):
        view = GatedCBV.as_view()
        response = view(self._request(at=None))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/security/", response["Location"])

    def test_mixin_factorless_user_passes_with_allow_unenrolled(self):
        view = PermissiveGatedCBV.as_view()
        response = view(self._request(at=None))
        self.assertEqual(response.status_code, 200)


class PickerNextTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.client.force_login(self.user)

    def _give_totp(self):
        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP,
            data={"secret": encrypt(generate_secret())})

    def test_single_factor_forward_keeps_next(self):
        self._give_totp()
        response = self.client.get(reverse("mfa:verify") + "?next=/thing/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response["Location"],
            reverse("mfa:verify_factor", args=["totp"]) + "?next=%2Fthing%2F")

    def test_single_factor_forward_drops_an_unsafe_next(self):
        self._give_totp()
        response = self.client.get(
            reverse("mfa:verify") + "?next=https://evil.example.com/")
        self.assertEqual(response["Location"],
                         reverse("mfa:verify_factor", args=["totp"]))

    def test_single_factor_forward_without_next_is_unchanged(self):
        self._give_totp()
        response = self.client.get(reverse("mfa:verify"))
        self.assertEqual(response["Location"],
                         reverse("mfa:verify_factor", args=["totp"]))

    def test_picker_links_carry_next(self):
        self._give_totp()
        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.RECOVERY_CODES,
            data={"codes": [], "used": []})
        response = self.client.get(reverse("mfa:verify") + "?next=/thing/")
        self.assertEqual(response.status_code, 200)
        # The picker.html link is built with the `urlencode` template filter,
        # not urllib.parse.urlencode -- Django's filter defaults to safe="/"
        # (see django.template.defaultfilters.urlencode), so "/" survives
        # unescaped here even though the single-factor redirect case below
        # (built with urllib.parse.urlencode, no safe param) percent-encodes
        # it to %2F. Both are safe; they're just two different encoders.
        self.assertContains(response, "?next=/thing/")

    def test_picker_links_omit_an_unsafe_next(self):
        self._give_totp()
        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.RECOVERY_CODES,
            data={"codes": [], "used": []})
        response = self.client.get(
            reverse("mfa:verify") + "?next=https://evil.example.com/")
        self.assertNotContains(response, "evil.example.com")


class GatedViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.client.force_login(self.user)

    def _verify(self, at):
        s = self.client.session
        s["mfa"] = {"verified": True, "method": "totp", "at": at}
        s.save()

    def _give_totp(self):
        return Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP,
            data={"secret": encrypt(generate_secret())})

    def test_stale_enroll_redirects(self):
        self._give_totp()
        self._verify(0)
        response = self.client.get(
            reverse("mfa:enroll_factor", args=["webauthn"]))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("mfa:verify"), response["Location"])

    def test_fresh_enroll_allowed(self):
        self._give_totp()
        self._verify(int(time.time()))
        response = self.client.get(
            reverse("mfa:enroll_factor", args=["webauthn"]))
        self.assertEqual(response.status_code, 200)

    def test_first_enrollment_is_never_gated(self):
        # LOAD-BEARING lockout regression: no factor yet, no verified session.
        response = self.client.get(reverse("mfa:enroll_factor", args=["totp"]))
        self.assertEqual(response.status_code, 200)

    def test_stale_removal_is_refused_and_keeps_the_factor(self):
        auth = self._give_totp()
        self._verify(0)
        response = self.client.post(reverse("mfa:manage"), {"pk": auth.pk})
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("mfa:verify"), response["Location"])
        self.assertTrue(Authenticator.objects.filter(pk=auth.pk).exists())

    def test_stale_removal_returns_to_security_settings_not_a_405(self):
        auth = self._give_totp()
        self._verify(0)
        response = self.client.post(reverse("mfa:manage"), {"pk": auth.pk})
        # redirect_to_login builds the querystring via
        # QueryDict.urlencode(safe="/"), which deliberately leaves "/"
        # unescaped -- see the matching comment on GateTests above.
        self.assertIn("next=" + reverse("mfa:security_settings"),
                      response["Location"])

    def test_fresh_removal_succeeds(self):
        auth = self._give_totp()
        self._verify(int(time.time()))
        response = self.client.post(reverse("mfa:manage"), {"pk": auth.pk})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Authenticator.objects.filter(pk=auth.pk).exists())

    def test_stale_recovery_code_regeneration_is_refused(self):
        self._give_totp()
        self._verify(0)
        response = self.client.get(reverse("mfa:recovery_codes"))
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Authenticator.objects.filter(
            user=self.user, type=Authenticator.Type.RECOVERY_CODES).exists())

    def test_first_recovery_codes_without_a_factor_are_not_gated(self):
        response = self.client.get(reverse("mfa:recovery_codes"))
        self.assertEqual(response.status_code, 200)

    @override_settings(MFA_STEPUP_MAX_AGE=None)
    def test_disabled_gate_restores_4_1_behaviour(self):
        auth = self._give_totp()
        self._verify(0)
        self.client.post(reverse("mfa:manage"), {"pk": auth.pk})
        self.assertFalse(Authenticator.objects.filter(pk=auth.pk).exists())

    @override_settings(MFA_STEPUP_MAX_AGE=None)
    def test_disabled_gate_restores_4_1_behaviour_for_a_factorless_user_too(self):
        # Fix round 1: the test above (and GateTests.
        # test_setting_none_disables_the_gate) both call _give_totp() first,
        # so they only exercise the population for which MFA_STEPUP_MAX_AGE
        # = None already worked -- a user WITH a primary factor. A user
        # whose only row is recovery_codes has none
        # (counts_as_primary_factor = False), and manage_factors used to
        # wall such a user to mfa:security_settings regardless of this
        # setting, because _enforce()'s factorless rung ran before
        # _enforce_recent() ever consulted MFA_STEPUP_MAX_AGE. That made
        # "restore 4.1.0 behaviour exactly" false for exactly this user.
        auth = Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.RECOVERY_CODES,
            data={"codes": [], "used": []})
        self._verify(0)
        self.client.post(reverse("mfa:manage"), {"pk": auth.pk})
        self.assertFalse(Authenticator.objects.filter(pk=auth.pk).exists())

    def test_security_settings_itself_is_never_gated(self):
        # The gate's own redirect target must not itself require freshness --
        # a stale user bounced here by manage_factors/enroll_factor/
        # recovery_codes has to be able to land, or the redirect loops
        # forever. Only implicitly covered elsewhere (test_views.py's
        # SecuritySettingsTests, which never stamps a stale session); pin
        # the invariant here by name, next to the rest of the gate's tests.
        self._give_totp()
        self._verify(0)
        response = self.client.get(reverse("mfa:security_settings"))
        self.assertEqual(response.status_code, 200)
