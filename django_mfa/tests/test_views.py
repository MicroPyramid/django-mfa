import base64
import json
import os
import re
import xml.etree.ElementTree as ET
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.cache import cache
from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import NoReverseMatch, reverse

from django_mfa import totp as totp_mod
from django_mfa.adapters.webauthn import WebAuthnAdapter
from django_mfa.crypto import encrypt
from django_mfa.models import Authenticator
from django_mfa.tests.support.authenticator import SoftwareAuthenticator
from django_mfa.views.verify import (
    GENERIC_ERROR,
    _generate_cookie_salt,
    delete_rmb_cookie,
    update_rmb_cookie,
    verify_rmb_cookie,
)


class PickerTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.client = Client()
        self.client.login(username="a@example.com", password="pw")

    def test_single_factor_redirects_straight_to_it(self):
        Authenticator.objects.create(user=self.user, type="totp")
        response = self.client.get(reverse("mfa:verify"))
        self.assertRedirects(
            response, reverse("mfa:verify_factor", args=["totp"]),
            fetch_redirect_response=False)

    def test_multiple_factors_render_a_choice(self):
        Authenticator.objects.create(user=self.user, type="totp")
        Authenticator.objects.create(user=self.user, type="recovery_codes",
                                     data={"codes": [], "used": []})
        response = self.client.get(reverse("mfa:verify"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "django_mfa/picker.html")


class VerifyFactorTests(TestCase):
    def setUp(self):
        cache.clear()  # rate-limit counters are keyed by user pk; sqlite can
        # reuse pks across TestCase-rolled-back transactions, so an earlier
        # test's counter could otherwise leak into this one.
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.secret = "JBSWY3DPEHPK3PXP"
        Authenticator.objects.create(user=self.user, type="totp",
                                     data={"secret": self.secret})
        self.client = Client()
        self.client.login(username="a@example.com", password="pw")

    def test_correct_code_marks_session_verified(self):
        response = self.client.post(
            reverse("mfa:verify_factor", args=["totp"]),
            {"code": totp_mod.TOTP(self.secret).now()})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(self.client.session["mfa"]["verified"])

    def test_wrong_code_returns_400_and_stays_unverified(self):
        response = self.client.post(
            reverse("mfa:verify_factor", args=["totp"]), {"code": "000000"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(self.client.session["mfa"]["verified"])

    def test_unknown_factor_is_404(self):
        # This user has a TOTP authenticator, so login (Task 21's
        # user_logged_in signal) marks the session pending. MfaMiddleware's
        # exempt set only covers *registered* factor verify paths, so an
        # unrecognised type like "nope" would otherwise be redirected to the
        # picker before the view gets a chance to 404 it. Mark the session
        # verified first so this test isolates the view's own
        # _adapter_or_404 behaviour, which is what it's actually checking --
        # the pending-gate redirect is covered separately by
        # test_enforcement.py.
        session = self.client.session
        session["mfa"] = {"verified": True, "method": "totp", "at": 0}
        session.save()
        response = self.client.get(reverse("mfa:verify_factor", args=["nope"]))
        self.assertEqual(response.status_code, 404)

    def test_lockout_response_is_indistinguishable_from_a_wrong_code(self):
        with self.settings(MFA_VERIFY_RATE_LIMIT="1/5m"):
            first = self.client.post(
                reverse("mfa:verify_factor", args=["totp"]), {"code": "000000"})
            second = self.client.post(
                reverse("mfa:verify_factor", args=["totp"]), {"code": "000000"})
        self.assertEqual(first.status_code, second.status_code)
        self.assertContains(second, "expired or invalid", status_code=400)

    def test_get_renders_verify_template(self):
        response = self.client.get(reverse("mfa:verify_factor", args=["totp"]))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "django_mfa/verify_totp.html")

    def test_external_next_is_not_honoured(self):
        """_safe_next() must reject an off-host `next` -- an unvalidated
        redirect target here is an open redirect."""
        response = self.client.post(
            reverse("mfa:verify_factor", args=["totp"])
            + "?next=https://evil.example/steal",
            {"code": totp_mod.TOTP(self.secret).now()})
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("evil.example", response.url)

    def test_same_host_next_is_honoured(self):
        response = self.client.post(
            reverse("mfa:verify_factor", args=["totp"]),
            {"code": totp_mod.TOTP(self.secret).now(), "next": "/somewhere/"})
        self.assertRedirects(response, "/somewhere/", fetch_redirect_response=False)

    def test_correct_code_is_still_blocked_once_rate_limited(self):
        with self.settings(MFA_VERIFY_RATE_LIMIT="1/5m"):
            self.client.post(reverse("mfa:verify_factor", args=["totp"]),
                             {"code": "000000"})
            # The single allowed attempt was just spent on a wrong code, so a
            # correct one right after should still be blocked...
            still_locked = self.client.post(
                reverse("mfa:verify_factor", args=["totp"]),
                {"code": totp_mod.TOTP(self.secret).now()})
            self.assertEqual(still_locked.status_code, 400)


class EnrollFactorTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.client = Client()
        self.client.login(username="a@example.com", password="pw")

    def _enroll_totp(self):
        get_response = self.client.get(reverse("mfa:enroll_factor", args=["totp"]))
        secret = get_response.context["secret_key"]
        code = totp_mod.TOTP(secret).now()
        return self.client.post(reverse("mfa:enroll_factor", args=["totp"]),
                                {"secret_key": secret, "code": code})

    def test_get_renders_enroll_template_with_secret_and_uri(self):
        response = self.client.get(reverse("mfa:enroll_factor", args=["totp"]))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "django_mfa/enroll_totp.html")
        self.assertIn("secret_key", response.context)
        self.assertTrue(
            response.context["provisioning_uri"].startswith("otpauth://totp/"))

    def test_get_renders_a_working_inline_qr_code(self):
        # Regression test: enrollment used to embed an <img> pointing at
        # chart.apis.google.com, a Google Charts endpoint decommissioned
        # years ago, so the QR code never actually rendered for any user.
        response = self.client.get(reverse("mfa:enroll_factor", args=["totp"]))
        content = response.content.decode()
        self.assertIn("data:image/svg+xml;base64,", content)
        self.assertNotIn("chart.apis.google.com", content)

        match = re.search(r'src="data:image/svg\+xml;base64,([^"]+)"', content)
        self.assertIsNotNone(match, "no inline SVG data URI in the response")
        payload = base64.b64decode(match.group(1))
        root = ET.fromstring(payload)
        self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")

    def test_unknown_factor_enroll_is_404(self):
        response = self.client.get(reverse("mfa:enroll_factor", args=["nope"]))
        self.assertEqual(response.status_code, 404)

    def test_valid_code_creates_authenticator_and_marks_session_verified(self):
        self._enroll_totp()
        self.assertTrue(
            Authenticator.objects.filter(user=self.user, type="totp").exists())
        self.assertTrue(self.client.session["mfa"]["verified"])
        self.assertEqual(self.client.session["mfa"]["method"], "totp")

    def test_first_enroll_with_no_recovery_codes_redirects_to_recovery_codes(self):
        response = self._enroll_totp()
        self.assertRedirects(response, reverse("mfa:recovery_codes"))

    def test_enroll_with_existing_recovery_codes_redirects_to_security_settings(self):
        Authenticator.objects.create(user=self.user, type="recovery_codes",
                                     data={"codes": [], "used": []})
        response = self._enroll_totp()
        self.assertRedirects(response, reverse("mfa:security_settings"))

    def test_wrong_code_returns_400_and_creates_nothing(self):
        get_response = self.client.get(reverse("mfa:enroll_factor", args=["totp"]))
        secret = get_response.context["secret_key"]
        response = self.client.post(reverse("mfa:enroll_factor", args=["totp"]),
                                    {"secret_key": secret, "code": "000000"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("error_message", response.context)
        self.assertFalse(
            Authenticator.objects.filter(user=self.user, type="totp").exists())


class AdapterFailureModeTests(TestCase):
    """Final whole-branch review, finding 2: five failure modes at the
    adapter/view seam used to raise straight through verify_factor/
    enroll_factor as unhandled 500s -- clone detection (ValueError), a
    tampered credential payload (TypeError), and a missing `credential`/
    `secret_key` POST field (KeyError / MultiValueDictKeyError, a KeyError
    subclass). Every one of them must now come back as the SAME 400 an
    ordinary wrong code produces -- both so nothing 500s, and so the
    500-vs-400 split itself can't be used as an oracle against the
    deliberately uniform failure response.
    """

    def setUp(self):
        cache.clear()  # rate-limit counters are keyed by user pk, which sqlite
        # reuses across rolled-back TestCases -- an earlier test's counter
        # would otherwise leak into the lockout tests below.
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.client = Client()
        self.client.login(username="a@example.com", password="pw")
        self.device = SoftwareAuthenticator(origin="https://testserver",
                                            rp_id="testserver")
        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            adapter = WebAuthnAdapter()
            request = RequestFactory().get("/", secure=True)
            request.user = self.user
            request.session = {}
            ctx = adapter.begin_enroll(request)
            credential = self.device.create(json.loads(ctx["options"]))
            self.auth = adapter.complete_enroll(
                request, {"credential": json.dumps(credential), "name": "k"})

    # -- verify_factor (webauthn) --------------------------------------------

    def _verify_webauthn(self, data):
        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            self.client.get(reverse("mfa:verify_factor", args=["webauthn"]))
            return self.client.post(
                reverse("mfa:verify_factor", args=["webauthn"]), data)

    def test_verify_ordinary_failure_is_the_baseline(self):
        """No prior begin_verify GET -> the auth state is missing and
        complete_verify() returns False, exactly as it always has. This is
        the "ordinary wrong code" response every other case in this class is
        compared against.
        """
        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            response = self.client.post(
                reverse("mfa:verify_factor", args=["webauthn"]),
                {"credential": "{}"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.context["error_message"], GENERIC_ERROR)

    def test_verify_clone_detection_is_400_not_500(self):
        self.auth.data["sign_count"] = 99
        self.auth.save()
        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            get_response = self.client.get(
                reverse("mfa:verify_factor", args=["webauthn"]))
            options = json.loads(get_response.context["options"])
            assertion = self.device.get(options)
            response = self.client.post(
                reverse("mfa:verify_factor", args=["webauthn"]),
                {"credential": json.dumps(assertion)})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.context["error_message"], GENERIC_ERROR)

    def test_verify_tampered_credential_shape_is_400_not_500(self):
        """A `credential` value that's valid JSON but not a mapping (e.g. a
        JSON array) makes fido2's own parsing raise TypeError, not
        ValueError -- confirmed against the installed fido2 2.2.1 directly
        (AuthenticationResponse.from_dict raises
        "... called with non-Mapping data ...").
        """
        response = self._verify_webauthn({"credential": json.dumps([1, 2, 3])})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.context["error_message"], GENERIC_ERROR)

    def test_verify_missing_credential_field_is_400_not_500(self):
        response = self._verify_webauthn({})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.context["error_message"], GENERIC_ERROR)

    def _genuine_assertion_response(self):
        """Drive a real, valid WebAuthn assertion through verify_factor."""
        get_response = self.client.get(
            reverse("mfa:verify_factor", args=["webauthn"]))
        options = json.loads(get_response.context["options"])
        assertion = self.device.get(options)
        return self.client.post(
            reverse("mfa:verify_factor", args=["webauthn"]),
            {"credential": json.dumps(assertion)})

    def test_caught_adapter_exception_counts_towards_the_lockout(self):
        """A caught adapter exception must not skip ratelimit.record_failure
        -- it has to count towards the lockout exactly like a plain wrong code
        would, or this failure mode would be a free, unlimited guessing
        oracle.

        Asserting that two failures merely *look* alike cannot detect that:
        the failure response is uniform by design, so it stays 400/
        GENERIC_ERROR whether or not the counter moved. The only observable
        that distinguishes "recorded" from "not recorded" is what happens to
        a subsequently *correct* credential -- so this drives a genuine
        assertion from the SoftwareAuthenticator and requires it to be
        refused. Delete record_failure from the exception path and this test
        fails (the genuine assertion is accepted, 302).
        """
        with self.settings(MFA_FIDO2_RP_ID="testserver",
                           MFA_VERIFY_RATE_LIMIT="1/5m"):
            caught = self._verify_webauthn({"credential": json.dumps([1, 2, 3])})
            self.assertEqual(caught.status_code, 400)
            response = self._genuine_assertion_response()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.context["error_message"], GENERIC_ERROR)
        self.assertFalse(self.client.session.get("mfa", {}).get("verified"))

    def test_control_genuine_assertion_succeeds_without_a_prior_failure(self):
        """Control for the test above: the same assertion, same 1/5m limit,
        with no preceding failure, IS accepted. Without this, that test would
        also pass if the SoftwareAuthenticator had simply stopped producing
        valid assertions.
        """
        with self.settings(MFA_FIDO2_RP_ID="testserver",
                           MFA_VERIFY_RATE_LIMIT="1/5m"):
            response = self._genuine_assertion_response()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(self.client.session["mfa"]["verified"])

    # -- enroll_factor (totp + webauthn) -------------------------------------

    def test_enroll_totp_missing_fields_is_400_not_500(self):
        response = self.client.post(reverse("mfa:enroll_factor", args=["totp"]), {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.context["error_message"], GENERIC_ERROR)

    def test_enroll_webauthn_missing_credential_field_is_400_not_500(self):
        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            self.client.get(reverse("mfa:enroll_factor", args=["webauthn"]))
            response = self.client.post(
                reverse("mfa:enroll_factor", args=["webauthn"]), {"name": "k2"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.context["error_message"], GENERIC_ERROR)

    def test_enroll_webauthn_tampered_credential_shape_is_400_not_500(self):
        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            self.client.get(reverse("mfa:enroll_factor", args=["webauthn"]))
            response = self.client.post(
                reverse("mfa:enroll_factor", args=["webauthn"]),
                {"credential": json.dumps([1, 2, 3]), "name": "k2"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.context["error_message"], GENERIC_ERROR)


class SecuritySettingsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.client = Client()
        self.client.login(username="a@example.com", password="pw")

    def test_renders_enabled_available_and_remaining(self):
        Authenticator.objects.create(user=self.user, type="totp")
        response = self.client.get(reverse("mfa:security_settings"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "django_mfa/security.html")
        self.assertEqual(
            [a.type for a in response.context["enabled_adapters"]], ["totp"])
        self.assertNotIn(
            "totp", [a.type for a in response.context["available_adapters"]])
        self.assertEqual(response.context["recovery_codes_remaining"], 0)

    def test_no_factors_still_renders(self):
        response = self.client.get(reverse("mfa:security_settings"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["enabled_adapters"], [])

    def test_every_add_a_method_link_actually_resolves(self):
        """The security page renders one "add" link per available_for()
        adapter. Recovery codes are generated, not enrolled, so offering them
        here pointed a fresh user straight at Adapter.begin_enroll's
        NotImplementedError -- a 500 on a link this package puts in front of
        every user who has no codes yet.

        Rather than pin the one factor that regressed, follow every link the
        page actually renders and require each to be servable. A future
        non-enrollable factor cannot reintroduce this without failing here.
        """
        response = self.client.get(reverse("mfa:security_settings"))
        links = re.findall(r'href="(/enroll/[^"]+)"', response.content.decode())
        self.assertTrue(links, "expected the page to offer at least one factor")
        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            for link in links:
                with self.subTest(link=link):
                    self.assertEqual(self.client.get(link).status_code, 200)

    def test_enrolling_a_generated_factor_directly_is_404_not_500(self):
        """available_for() keeps recovery codes off the page; this covers the
        hand-typed URL, which would otherwise reach begin_enroll and 500.
        """
        response = self.client.get(
            reverse("mfa:enroll_factor", args=["recovery_codes"]))
        self.assertEqual(response.status_code, 404)

    def test_page_lists_authenticator_with_a_removal_form(self):
        """Final whole-branch review, finding 5: security.html has no way to
        remove a factor at all -- no form posts to mfa:manage, and no
        authenticator primary keys are even exposed. This is the regression
        guard: the removal form (posting to mfa:manage, carrying this
        authenticator's own pk) must actually be present in the rendered
        page, not just work if you already know the URL and pk.
        """
        auth = Authenticator.objects.create(user=self.user, type="totp")
        response = self.client.get(reverse("mfa:security_settings"))
        content = response.content.decode()
        self.assertIn(reverse("mfa:manage"), content)
        self.assertIn(f'value="{auth.pk}"', content)

    def test_a_user_can_delete_their_own_authenticator_through_the_rendered_page(self):
        auth = Authenticator.objects.create(user=self.user, type="totp")
        get_response = self.client.get(reverse("mfa:security_settings"))
        self.assertIn(f'value="{auth.pk}"', get_response.content.decode())

        post_response = self.client.post(reverse("mfa:manage"), {"pk": auth.pk})
        self.assertRedirects(post_response, reverse("mfa:security_settings"))
        self.assertFalse(Authenticator.objects.filter(pk=auth.pk).exists())

    def test_webauthn_credential_lists_its_own_name_and_created_date(self):
        auth = Authenticator.objects.create(
            user=self.user, type="webauthn", name="YubiKey 5C")
        response = self.client.get(reverse("mfa:security_settings"))
        content = response.content.decode()
        self.assertIn("YubiKey 5C", content)
        self.assertIn(str(auth.created_at.year), content)

    def test_webauthn_removal_form_present_when_not_enterprise_owned(self):
        auth = Authenticator.objects.create(
            user=self.user, type="webauthn", name="key")
        response = self.client.get(reverse("mfa:security_settings"))
        self.assertIn(f'value="{auth.pk}"', response.content.decode())

    @override_settings(MFA_OWNED_BY_ENTERPRISE=True)
    def test_webauthn_removal_form_absent_when_enterprise_owned(self):
        auth = Authenticator.objects.create(
            user=self.user, type="webauthn", name="key")
        response = self.client.get(reverse("mfa:security_settings"))
        content = response.content.decode()
        # Still listed (name visible)...
        self.assertIn("key", content)
        # ...but its pk must not appear as a removal form's hidden value.
        self.assertNotIn(f'value="{auth.pk}"', content)

    @override_settings(MFA_OWNED_BY_ENTERPRISE=True)
    def test_totp_removal_form_still_present_when_enterprise_owned(self):
        """MFA_OWNED_BY_ENTERPRISE only restricts WebAuthn removal (see
        manage_factors in views/manage.py) -- the page must reflect that,
        not blanket-hide every removal form.
        """
        auth = Authenticator.objects.create(user=self.user, type="totp")
        response = self.client.get(reverse("mfa:security_settings"))
        self.assertIn(f'value="{auth.pk}"', response.content.decode())


class RecoveryCodesViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.client = Client()
        self.client.login(username="a@example.com", password="pw")

    def test_first_view_generates_ten_codes(self):
        response = self.client.get(reverse("mfa:recovery_codes"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "django_mfa/recovery_codes.html")
        self.assertEqual(len(response.context["codes"]), 10)

    def test_codes_are_hashed_at_rest(self):
        response = self.client.get(reverse("mfa:recovery_codes"))
        shown = response.context["codes"]
        auth = Authenticator.objects.get(user=self.user, type="recovery_codes")
        self.assertNotIn(shown[0], auth.data["codes"])

    def test_revisit_in_a_fresh_session_does_not_show_codes_again(self):
        """Codes are hashed once stored, so only the response that triggered
        generate() ever carries the plaintext -- nothing server-side keeps a
        copy afterwards (see the session test below)."""
        first = self.client.get(reverse("mfa:recovery_codes"))
        self.assertTrue(first.context["codes"])

        other_client = Client()
        other_client.login(username="a@example.com", password="pw")
        second = other_client.get(reverse("mfa:recovery_codes"))
        self.assertIsNone(second.context["codes"])

    def test_no_plaintext_code_ever_reaches_the_session(self):
        """Regression test: the server must never retain plaintext recovery
        codes anywhere, including the session -- they are shown once, in the
        response body, and nowhere else. The client builds its own download
        from the rendered page (see recovery_codes.html); the server must
        not stash a copy to serve later.

        Checked against a stringified dump of the whole session rather than
        just the top-level values: a value nested one level down (e.g. the
        codes stored as a list under some session key) would not match a
        plain `code in session.values()` check, but would still mean the
        server is holding onto plaintext codes.
        """
        response = self.client.get(reverse("mfa:recovery_codes"))
        codes = response.context["codes"]
        self.assertEqual(len(codes), 10)

        session_dump = repr(dict(self.client.session))
        for code in codes:
            self.assertNotIn(code, session_dump)

    def test_download_url_no_longer_exists(self):
        """The plaintext-serving download endpoint is gone -- downloading is
        now built client-side from the codes already in the page."""
        with self.assertRaises(NoReverseMatch):
            reverse("mfa:recovery_codes_download")

    def test_page_renders_one_recovery_code_element_per_code(self):
        """The client-side download script (in recovery_codes.html) selects
        on `.recovery-code` to build the file it offers -- if the template
        stops emitting that class, the download silently breaks."""
        response = self.client.get(reverse("mfa:recovery_codes"))
        codes = response.context["codes"]
        content = response.content.decode()
        self.assertEqual(content.count('class="recovery-code"'), len(codes))


class ManageFactorsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.other = User.objects.create_user("b@example.com", password="pw")
        self.client = Client()
        self.client.login(username="a@example.com", password="pw")

    def test_deletes_own_authenticator_and_redirects(self):
        auth = Authenticator.objects.create(user=self.user, type="totp")
        response = self.client.post(reverse("mfa:manage"), {"pk": auth.pk})
        self.assertRedirects(response, reverse("mfa:security_settings"))
        self.assertFalse(Authenticator.objects.filter(pk=auth.pk).exists())

    def test_cannot_delete_another_users_authenticator(self):
        auth = Authenticator.objects.create(user=self.other, type="totp")
        response = self.client.post(reverse("mfa:manage"), {"pk": auth.pk})
        self.assertEqual(response.status_code, 404)
        self.assertTrue(Authenticator.objects.filter(pk=auth.pk).exists())

    def test_unparseable_pk_is_404_not_500(self):
        """get_object_or_404 only catches DoesNotExist, but the ORM raises
        ValueError first when the pk can't be coerced to an int -- so a
        non-numeric pk used to 500 where a missing or someone-else's pk
        correctly 404s.
        """
        for bad_pk in ("abc", "", "1; DROP TABLE", "9999999999999999999999"):
            with self.subTest(pk=bad_pk):
                response = self.client.post(reverse("mfa:manage"), {"pk": bad_pk})
                self.assertEqual(response.status_code, 404)

    def test_missing_pk_is_404_not_500(self):
        response = self.client.post(reverse("mfa:manage"), {})
        self.assertEqual(response.status_code, 404)

    def test_get_is_not_allowed(self):
        response = self.client.get(reverse("mfa:manage"))
        self.assertEqual(response.status_code, 405)

    def test_webauthn_deletion_allowed_when_not_enterprise_owned(self):
        auth = Authenticator.objects.create(user=self.user, type="webauthn")
        response = self.client.post(reverse("mfa:manage"), {"pk": auth.pk})
        self.assertRedirects(response, reverse("mfa:security_settings"))
        self.assertFalse(Authenticator.objects.filter(pk=auth.pk).exists())

    @override_settings(MFA_OWNED_BY_ENTERPRISE=True)
    def test_webauthn_deletion_forbidden_when_enterprise_owned(self):
        auth = Authenticator.objects.create(user=self.user, type="webauthn")
        response = self.client.post(reverse("mfa:manage"), {"pk": auth.pk})
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Authenticator.objects.filter(pk=auth.pk).exists())

    @override_settings(MFA_OWNED_BY_ENTERPRISE=True)
    def test_enterprise_owned_only_restricts_webauthn(self):
        auth = Authenticator.objects.create(user=self.user, type="totp")
        response = self.client.post(reverse("mfa:manage"), {"pk": auth.pk})
        self.assertRedirects(response, reverse("mfa:security_settings"))
        self.assertFalse(Authenticator.objects.filter(pk=auth.pk).exists())


@override_settings(MFA_REMEMBER_MY_BROWSER=True, MFA_REMEMBER_DAYS=1)
class RememberMyBrowserTests(TestCase):
    """verify_rmb_cookie / update_rmb_cookie / delete_rmb_cookie carried over
    from the legacy views.py, now reading Authenticator (type=totp,
    data["secret"], possibly encrypted) instead of UserOTP.secret_key."""

    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.factory = RequestFactory()
        Authenticator.objects.create(
            user=self.user, type="totp",
            data={"secret": encrypt("JBSWY3DPEHPK3PXP")})

    def _request(self):
        request = self.factory.get("/")
        request.user = self.user
        request.COOKIES = {}
        return request

    def test_verify_false_before_any_cookie_is_set(self):
        self.assertFalse(verify_rmb_cookie(self._request()))

    def test_update_then_verify_round_trips(self):
        response = update_rmb_cookie(self._request(), HttpResponse())
        cookie_name = "RMB_" + str(self.user.pk)

        verify_request = self._request()
        verify_request.COOKIES[cookie_name] = response.cookies[cookie_name].value

        self.assertTrue(verify_rmb_cookie(verify_request))

    def test_verify_false_when_feature_disabled(self):
        response = update_rmb_cookie(self._request(), HttpResponse())
        cookie_name = "RMB_" + str(self.user.pk)

        verify_request = self._request()
        verify_request.COOKIES[cookie_name] = response.cookies[cookie_name].value

        with override_settings(MFA_REMEMBER_MY_BROWSER=False):
            self.assertFalse(verify_rmb_cookie(verify_request))

    def test_delete_expires_the_cookie(self):
        response = delete_rmb_cookie(self._request(), HttpResponse())
        cookie_name = "RMB_" + str(self.user.pk)
        self.assertEqual(response.cookies[cookie_name]["max-age"], 0)
        self.assertEqual(response.cookies[cookie_name].value, "")

    def test_generate_cookie_salt_uses_the_decrypted_secret(self):
        self.assertTrue(_generate_cookie_salt(self.user))

    def test_generate_cookie_salt_empty_without_a_totp_authenticator(self):
        other = User.objects.create_user("b@example.com", password="pw")
        self.assertEqual(_generate_cookie_salt(other), "")

    def test_verify_false_without_a_totp_authenticator(self):
        other = User.objects.create_user("c@example.com", password="pw")
        request = self.factory.get("/")
        request.user = other
        request.COOKIES = {}
        self.assertFalse(verify_rmb_cookie(request))


class WebAuthnTemplateTests(TestCase):
    """enroll_webauthn.html / verify_webauthn.html + webauthn.js.

    WebAuthnAdapter.begin_enroll()/begin_verify() (task 15/16) hand the view
    context["options"] as an already-JSON-encoded *string* -- see
    adapters/webauthn.py's `json.dumps(dict(options))`. That is the trap
    these templates have to avoid: naively piping that string through
    `{{ options|json_script:"..." }}` would json.dumps() a string, embedding
    doubly-encoded JSON that a single JSON.parse() in webauthn.js would turn
    back into a JS *string*, not the options object -- a bug that only shows
    up in a real browser. test_options_are_embedded_once_not_double_encoded
    below is the regression guard for that.
    """

    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.client = Client()
        self.client.login(username="a@example.com", password="pw")

    @staticmethod
    def _create_webauthn_authenticator(user, name="key"):
        """Store a real, verifiable credential for `user` -- not just a bare
        Authenticator row. begin_verify()'s allow-list building
        (_existing_credentials()) parses `data["credential_data"]` back into
        an AttestedCredentialData, so a row created without a real one (as
        Authenticator.objects.create(user=user, type="webauthn") alone would
        produce) makes the verify page 500 instead of rendering."""
        adapter = WebAuthnAdapter()
        device = SoftwareAuthenticator(origin="https://testserver",
                                       rp_id="testserver")
        request = RequestFactory().get("/", secure=True)
        request.user = user
        request.session = {}
        ctx = adapter.begin_enroll(request)
        credential = device.create(json.loads(ctx["options"]))
        return adapter.complete_enroll(
            request, {"credential": json.dumps(credential), "name": name})

    @staticmethod
    def _extract_options_script(html):
        match = re.search(
            r'<script id="webauthn-options" type="application/json">'
            r'(.*?)</script>',
            html, re.S)
        return match.group(1) if match else None

    def test_enroll_page_embeds_options_and_script(self):
        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            response = self.client.get(
                reverse("mfa:enroll_factor", args=["webauthn"]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "django_mfa/webauthn.js")
        self.assertContains(response, 'id="webauthn-options"')

    def test_verify_page_embeds_options_and_script(self):
        self._create_webauthn_authenticator(self.user)
        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            response = self.client.get(
                reverse("mfa:verify_factor", args=["webauthn"]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "django_mfa/webauthn.js")
        self.assertContains(response, 'id="webauthn-options"')

    def test_enroll_form_posts_credential_and_name(self):
        """complete_enroll() reads POST["credential"] and POST["name"] (see
        adapters/webauthn.py) -- the form must offer exactly those field
        names."""
        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            response = self.client.get(
                reverse("mfa:enroll_factor", args=["webauthn"]))
        content = response.content.decode()
        self.assertIn('id="webauthn-form"', content)
        self.assertIn('data-mode="create"', content)
        self.assertRegex(content, r'<input[^>]+name="credential"')
        self.assertRegex(content, r'<input[^>]+name="name"')

    def test_verify_form_posts_credential(self):
        """complete_verify() reads only POST["credential"]."""
        self._create_webauthn_authenticator(self.user)
        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            response = self.client.get(
                reverse("mfa:verify_factor", args=["webauthn"]))
        content = response.content.decode()
        self.assertIn('id="webauthn-form"', content)
        self.assertIn('data-mode="get"', content)
        self.assertRegex(content, r'<input[^>]+name="credential"')

    def test_unsupported_message_present_but_hidden_by_default(self):
        """A browser without window.PublicKeyCredential must see a clear
        message rather than a silent failure or a thrown exception -- the
        template must render the element (hidden), and webauthn.js reveals
        it (checked separately, since no browser runs here -- see
        WebAuthnJsSourceTests)."""
        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            response = self.client.get(
                reverse("mfa:enroll_factor", args=["webauthn"]))
        content = response.content.decode()
        self.assertRegex(
            content, r'<[^>]*id="webauthn-unsupported"[^>]*\bhidden\b')

    def test_options_are_embedded_once_not_double_json_encoded(self):
        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            response = self.client.get(
                reverse("mfa:enroll_factor", args=["webauthn"]))
        raw = self._extract_options_script(response.content.decode())
        self.assertIsNotNone(raw, "no <script id=webauthn-options> found")

        # A single json.loads() (standing in for the browser's single
        # JSON.parse()) must yield the options dict itself, not a string
        # containing more JSON text.
        parsed = json.loads(raw)
        self.assertIsInstance(parsed, dict)
        self.assertIn("publicKey", parsed)
        self.assertIsInstance(parsed["publicKey"]["challenge"], str)
        self.assertIsInstance(parsed["publicKey"]["user"]["id"], str)

    def test_verify_options_allow_credentials_present_and_decodable(self):
        self._create_webauthn_authenticator(self.user)
        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            response = self.client.get(
                reverse("mfa:verify_factor", args=["webauthn"]))
        raw = self._extract_options_script(response.content.decode())
        parsed = json.loads(raw)
        self.assertIsInstance(parsed["publicKey"]["challenge"], str)

    def test_full_enroll_round_trip_via_rendered_options(self):
        """End-to-end integration proof (still no real browser/JS -- see the
        task report): GET the real enroll page, take the options exactly as
        they were rendered in the <script id=webauthn-options> block, run
        them through the SoftwareAuthenticator test harness the way
        navigator.credentials.create() would, and POST the resulting
        credential plus a name to the same URL through the field names
        webauthn-form actually offers. If the template's options shape,
        script id, or field names ever drifted from what
        adapters/webauthn.py expects, this would fail.
        """
        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            get_response = self.client.get(
                reverse("mfa:enroll_factor", args=["webauthn"]))
        options = json.loads(
            self._extract_options_script(get_response.content.decode()))
        device = SoftwareAuthenticator(origin="https://testserver",
                                       rp_id="testserver")
        credential = device.create(options)

        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            post_response = self.client.post(
                reverse("mfa:enroll_factor", args=["webauthn"]),
                {"credential": json.dumps(credential), "name": "Integration key"})

        self.assertEqual(post_response.status_code, 302)
        self.assertTrue(Authenticator.objects.filter(
            user=self.user, type="webauthn", name="Integration key").exists())

    def test_full_verify_round_trip_via_rendered_options(self):
        """Same idea as the enroll round trip, for the verify page: enroll a
        real credential directly through the adapter, then drive the
        *rendered verify page's* options through the same software
        authenticator and POST the assertion through the field
        webauthn-form actually offers."""
        device = SoftwareAuthenticator(origin="https://testserver",
                                       rp_id="testserver")
        adapter = WebAuthnAdapter()
        enroll_request = RequestFactory().get("/", secure=True)
        enroll_request.user = self.user
        enroll_request.session = {}
        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            ctx = adapter.begin_enroll(enroll_request)
            credential = device.create(json.loads(ctx["options"]))
            adapter.complete_enroll(
                enroll_request,
                {"credential": json.dumps(credential), "name": "k"})

            get_response = self.client.get(
                reverse("mfa:verify_factor", args=["webauthn"]))
        options = json.loads(
            self._extract_options_script(get_response.content.decode()))
        assertion = device.get(options)

        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            post_response = self.client.post(
                reverse("mfa:verify_factor", args=["webauthn"]),
                {"credential": json.dumps(assertion)})

        self.assertEqual(post_response.status_code, 302)
        self.assertTrue(self.client.session["mfa"]["verified"])

    def test_hostile_option_value_cannot_break_out_of_script_tag(self):
        """The options come from the server, not the client, so this is
        defence in depth rather than a live attack path -- but a value that
        happens to contain "</script>" (e.g. an unusual username reflected
        into publicKey.user.name/displayName) must not be able to close the
        <script type="application/json"> block and inject a sibling
        <script> element.
        """
        hostile = {
            "publicKey": {
                "challenge": "abc123",
                "rp": {"id": "testserver", "name": "django-mfa"},
                "user": {
                    "id": "def456",
                    "name": "</script><script>alert(1)</script>",
                    "displayName": "attacker",
                },
                "pubKeyCredParams": [],
            }
        }
        hostile_json = json.dumps(hostile)
        with patch.object(WebAuthnAdapter, "begin_enroll",
                          return_value={"options": hostile_json}):
            with self.settings(MFA_FIDO2_RP_ID="testserver"):
                response = self.client.get(
                    reverse("mfa:enroll_factor", args=["webauthn"]))
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()

        # The dangerous substring must never appear literally: if it did,
        # the injected <script>alert(1)</script> would run as a second,
        # attacker-controlled script element.
        self.assertNotIn("</script><script>alert(1)</script>", content)
        # json_script (via django.utils.html.json_script) represents "<"
        # inside the JSON text as the unicode escape \u003C, never as a
        # literal character -- confirms real escaping ran, not just luck.
        self.assertIn("\\u003C/script\\u003E", content)

        # It must still be valid, single-encoded JSON: parsing the embedded
        # block once returns exactly the original dict.
        raw = self._extract_options_script(content)
        self.assertEqual(json.loads(raw), hostile)


class WebAuthnBase64UrlPortTests(TestCase):
    """Proves the base64url<->ArrayBuffer conversion webauthn.js implements
    (b64urlToBuf / bufToB64url) round-trips correctly, by porting the exact
    same algorithm (translate the URL-safe alphabet back to standard
    base64, restore/strip padding) into Python and testing it two ways:

    1. against Python's own `base64.urlsafe_b64encode`/`urlsafe_b64decode`
       (padding stripped), which is the same RFC 4648 base64url convention;
    2. against `fido2.utils.websafe_encode`/`websafe_decode`, the exact
       function the SERVER side (adapters/webauthn.py, via Fido2Server)
       uses to produce/consume `challenge`, `user.id`, and credential `id`.

    What this proves: the algorithm is correct RFC 4648 base64url and
    round-trips for arbitrary byte strings, including the empty string and
    lengths that require every padding case (0/1/2/3 leftover bytes).

    What this does NOT prove: that atob()/btoa()/Uint8Array/ArrayBuffer
    behave this way in an actual browser, that webauthn.js's own copy of
    this logic is free of a transcription typo, or that
    navigator.credentials.create()/get() accept the resulting ArrayBuffers.
    No JavaScript was executed to produce this test -- see the task report.
    """

    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.client = Client()
        self.client.login(username="a@example.com", password="pw")

    @staticmethod
    def b64url_to_buf(value):
        """Python port of webauthn.js's b64urlToBuf()."""
        remainder = len(value) % 4
        pad = "=" * (4 - remainder) if remainder else ""
        base64_str = (value + pad).replace("-", "+").replace("_", "/")
        return base64.b64decode(base64_str)

    @staticmethod
    def buf_to_b64url(buf):
        """Python port of webauthn.js's bufToB64url()."""
        encoded = base64.b64encode(buf).decode("ascii")
        return encoded.replace("+", "-").replace("/", "_").rstrip("=")

    def test_round_trip_every_padding_case(self):
        # Lengths 0..7 cover every value of (length % 4), i.e. every padding
        # case the real fields (challenge/id, arbitrary byte lengths) can
        # land on.
        for length in range(0, 40):
            data = bytes((i * 37 + 5) % 256 for i in range(length))
            encoded = self.buf_to_b64url(data)
            self.assertNotIn("+", encoded)
            self.assertNotIn("/", encoded)
            self.assertNotIn("=", encoded)
            self.assertEqual(self.b64url_to_buf(encoded), data)

    def test_matches_pythons_urlsafe_b64_with_padding_stripped(self):
        for length in range(0, 40):
            data = bytes((i * 91 + 3) % 256 for i in range(length))
            expected = base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
            self.assertEqual(self.buf_to_b64url(data), expected)
            self.assertEqual(self.b64url_to_buf(expected), data)

    def test_matches_fido2_websafe_encode_decode(self):
        from fido2.utils import websafe_decode, websafe_encode

        for length in (0, 1, 16, 32, 64):
            data = os.urandom(length)
            server_encoded = websafe_encode(data)
            self.assertEqual(self.buf_to_b64url(data), server_encoded)
            self.assertEqual(self.b64url_to_buf(server_encoded), data)
            self.assertEqual(websafe_decode(self.buf_to_b64url(data)), data)

    def test_round_trips_a_real_challenge_and_user_id_from_the_adapter(self):
        """Not just made-up vectors: decode/re-encode the actual base64url
        challenge and user.id a real enroll page embeds, the way
        webauthn.js's decodeOptions()/encodeCredential() would."""
        with self.settings(MFA_FIDO2_RP_ID="testserver"):
            response = self.client.get(
                reverse("mfa:enroll_factor", args=["webauthn"]))
        match = re.search(
            r'<script id="webauthn-options" type="application/json">'
            r'(.*?)</script>',
            response.content.decode(), re.S)
        options = json.loads(match.group(1))["publicKey"]

        for value in (options["challenge"], options["user"]["id"]):
            buf = self.b64url_to_buf(value)
            self.assertEqual(self.buf_to_b64url(buf), value)


class WebAuthnJsSourceTests(TestCase):
    """Static checks against the shipped webauthn.js source.

    No JavaScript engine/browser runs here, so these cannot prove the
    script behaves correctly -- only that the specific pieces the templates
    and the server-side adapter contract rely on are actually present in
    the file that ships. See the task report for what these do not prove.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        js_path = os.path.join(
            os.path.dirname(__file__), "..", "static", "django_mfa", "webauthn.js")
        with open(js_path) as fh:
            cls.source = fh.read()

    def test_file_exists_and_is_non_trivial(self):
        self.assertGreater(len(self.source), 500)

    def test_decodes_challenge_user_id_and_both_credential_lists(self):
        """The most likely bug per the task brief: handling challenge but
        forgetting that excludeCredentials/allowCredentials are ARRAYS of
        objects each carrying an id that also needs decoding."""
        for needle in ("pk.challenge", "pk.user.id",
                       "excludeCredentials", "allowCredentials"):
            self.assertIn(needle, self.source)

    def test_reveals_unsupported_message_when_publickeycredential_missing(self):
        self.assertIn("window.PublicKeyCredential", self.source)
        self.assertIn("webauthn-unsupported", self.source)
        self.assertIn("unsupported.hidden = false", self.source)

    def test_posts_credential_via_form_submit(self):
        self.assertIn("name=credential", self.source)
        self.assertIn("form.submit()", self.source)

    def test_uses_get_client_extension_results_method_not_a_property(self):
        """credential.clientExtensionResults is not a real property on the
        PublicKeyCredential navigator.credentials.create() resolves with --
        the only way to read extension outputs is the
        getClientExtensionResults() method. Reading a plain property here
        would always be undefined, silently breaking resident-key detection
        in every real browser."""
        self.assertIn("getClientExtensionResults", self.source)
        self.assertNotIn("credential.clientExtensionResults", self.source)


class HiddenAttributeStylesheetTests(TestCase):
    """The shipped stylesheet must not defeat the HTML `hidden` attribute.

    Found by driving the sandbox in a real browser (Chrome, CDP virtual
    authenticator) -- not by any test in this suite, and not reachable by
    one: it is a CSS *cascade* outcome, which requires a browser to compute.

    `webauthn.js` reveals its error/unsupported banners by toggling the
    `hidden` property, and the templates render them with `hidden` set.
    `hidden` is implemented by a user-agent rule, `[hidden] {display:none}`,
    whose specificity is lower than ANY class selector that sets `display` --
    and style.css has one (`.help-block {display:block}`) that matches those
    exact elements. The result was that "Your browser does not support
    security keys or passkeys (WebAuthn)" was permanently visible on the
    enroll AND verify pages of every browser that fully supports WebAuthn,
    directly above a working button.

    This test can only pin that the corrective rule is still present; the
    cascade itself was verified in the browser.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        css_path = os.path.join(
            os.path.dirname(__file__), "..", "static", "django_mfa", "style.css")
        with open(css_path) as fh:
            cls.raw = fh.read()
        # Strip comments before matching: the rule is explained by a comment
        # that necessarily quotes the UA rule it is defeating, and matching
        # that instead of the real declaration would make this test pass on a
        # stylesheet that only *talks* about [hidden].
        cls.source = re.sub(r"/\*.*?\*/", "", cls.raw, flags=re.DOTALL)

    def test_hidden_attribute_rule_is_present_and_wins(self):
        match = re.search(r"\[hidden\]\s*\{([^}]*)\}", self.source)
        self.assertIsNotNone(
            match, "style.css must carry a [hidden] rule -- see this class's "
                   "docstring for what breaks without it")
        body = match.group(1)
        self.assertIn("display", body)
        self.assertIn("none", body)
        # Without !important a later/equal-specificity class rule setting
        # `display` still wins, which is the exact bug this guards.
        self.assertIn("!important", body)

    def test_hidden_rule_precedes_every_display_setting_class_rule(self):
        """Order matters for equal specificity, and `!important` on the UA-
        level rule is what actually settles it -- but keeping the rule ahead
        of the class rules it protects makes the intent legible to whoever
        edits this file next.

        Checks EVERY class rule that sets `display`, not just `.help-block`.
        The earlier version named that one selector, so it kept passing as
        new display-setting classes were added after it -- including
        `.mfa-alert`, which is on the very banner this guards.
        """
        hidden_at = self.source.index("[hidden]")
        offenders = [
            (m.start(), m.group(1).strip())
            for m in re.finditer(r"(\.[\w-]+[^{}]*)\{([^}]*)\}", self.source)
            if re.search(r"(^|;)\s*display\s*:", m.group(2))
        ]
        self.assertTrue(
            offenders,
            "expected at least one class rule setting `display` -- if none "
            "remain, this guard is no longer testing anything")
        too_early = [name for at, name in offenders if at < hidden_at]
        self.assertEqual(
            too_early, [],
            f"these class rules set `display` before the [hidden] rule: "
            f"{too_early}")
