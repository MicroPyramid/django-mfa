# django_mfa/tests/test_passwordless.py
#
# Passwordless (passkey) login: django_mfa.backends.WebAuthnBackend and
# django_mfa.views.verify.passkey_begin/passkey_complete.
#
# Adapted from the task-18 brief with several corrections the brief predates
# -- see task-18-report.md for the full list. The two structural ones that
# affect test *shape* (not just implementation) are:
#
#   1. user_handle_for()/user_from_handle() are re-exported from
#      django_mfa.handles (a stored MfaUserHandle row), not the
#      django.core.signing scheme the brief's UserHandleTests assumed. The
#      brief's own test bodies still pass unchanged against the real
#      implementation, so they're kept close to verbatim.
#
#   2. The brief's QuickLoginTests use django.test.Client.login(), then
#      assert a cookie shows up on self.client.cookies. Empirically (see
#      django.test.client.Client._login in Django 4.2.30), Client.login()
#      fabricates a bare HttpRequest and calls django.contrib.auth.login()
#      against it directly -- it never produces an HttpResponse at all, let
#      alone runs it through any middleware. There is therefore no response
#      for a cookie-setting receiver/middleware to ever attach a cookie to,
#      and no implementation of "set a cookie on login" could make that
#      literal test pass. QuickLoginTests below instead drives a real
#      request -> response cycle with RequestFactory + MfaMiddleware
#      directly, exactly mirroring the pattern
#      test_enforcement.RememberMyBrowserEnforcementTests already uses for
#      the same reason (see that file's _login_with_cookies docstring).
import hashlib
import json
from base64 import urlsafe_b64encode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.contrib.auth import login as auth_login
from django.contrib.auth.models import User
from django.contrib.sessions.backends.db import SessionStore
from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import reverse
from fido2.webauthn import AuthenticatorData

from django_mfa.backends import user_from_handle, user_handle_for
from django_mfa.conf import settings as mfa_settings
from django_mfa.middleware import MfaMiddleware
from django_mfa.models import Authenticator
from django_mfa.tests.support.authenticator import SoftwareAuthenticator

FLAG_UP = AuthenticatorData.FLAG.UP


class UserHandleTests(TestCase):
    """Confirms django_mfa.backends actually re-exports handles.py's
    functions (the brief's stated interface contract) rather than
    redefining them -- see the module docstring on django_mfa/handles.py for
    why a second, signing-based implementation must not reappear here.
    """

    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")

    def test_handle_round_trips(self):
        self.assertEqual(user_from_handle(user_handle_for(self.user)), self.user)

    def test_handle_does_not_contain_the_username(self):
        self.assertNotIn("a@example.com", user_handle_for(self.user))

    def test_tampered_handle_returns_none(self):
        self.assertIsNone(user_from_handle(user_handle_for(self.user) + "x"))

    def test_handle_survives_a_username_change(self):
        handle = user_handle_for(self.user)
        self.user.username = "renamed@example.com"
        self.user.save()
        self.assertEqual(user_from_handle(handle), self.user)


class _UpOnlyAuthenticator(SoftwareAuthenticator):
    """A software authenticator whose assertions carry User Present but
    never User Verified -- e.g. a security key with no PIN/biometric set up.
    MFA_FIDO2_USER_VERIFICATION defaults to "preferred", not "required", so
    fido2's own authenticate_complete() does not reject this outright (see
    Fido2Server.authenticate_complete in fido2/server.py: it only enforces
    UV when state["user_verification"] == REQUIRED) -- whether a UP-only
    login still counts as satisfying BOTH MFA factors is therefore squarely
    django_mfa's own decision to get right, not something the library
    enforces for us. This class exists purely to produce that assertion
    shape for test_up_only_assertion_* below.

    Duplicates the body of SoftwareAuthenticator.get() rather than
    parameterising flags there: unlike sign_count (a plain instance
    attribute _CounterlessAuthenticator in test_adapter_webauthn.py
    overrides via a property), the flag set is a literal expression inline
    in get(), not read from any overridable attribute.
    """

    def get(self, options, user_handle=None):
        from django_mfa.tests.support.authenticator import b64url

        pk = options["publicKey"]
        self.sign_count += 1
        auth_data = AuthenticatorData.create(
            self._rp_id_hash(), FLAG_UP, self.sign_count)
        client_data = self._client_data("webauthn.get", pk["challenge"])
        signature = self.private_key.sign(
            bytes(auth_data) + hashlib.sha256(client_data).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "authenticatorData": b64url(auth_data),
                "signature": b64url(signature),
                "userHandle": b64url(user_handle) if user_handle else None,
            },
        }


@override_settings(
    MFA_FIDO2_RP_ID="testserver",
    ALLOWED_HOSTS=["testserver"],
    AUTHENTICATION_BACKENDS=["django_mfa.backends.WebAuthnBackend",
                             "django.contrib.auth.backends.ModelBackend"],
)
class PasswordlessLoginTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.device = SoftwareAuthenticator(origin="https://testserver",
                                            rp_id="testserver")
        self.client = Client()
        self._enroll()

    def _enroll(self):
        self.client.login(username="a@example.com", password="pw")
        response = self.client.get(reverse("mfa:enroll_factor", args=["webauthn"]))
        options = json.loads(response.context["options"])
        credential = self.device.create(options)
        self.client.post(reverse("mfa:enroll_factor", args=["webauthn"]),
                         {"credential": json.dumps(credential), "name": "passkey"})
        self.client.logout()

    def _handle_bytes(self, user):
        return user_handle_for(user).encode("utf-8")

    # -- Core ceremony: property 2 (a valid assertion actually authenticates) --

    def test_passkey_login_authenticates_without_a_password(self):
        begin = self.client.get(reverse("mfa:passkey_begin"))
        assertion = self.device.get(json.loads(begin.json()["options"]))
        response = self.client.post(reverse("mfa:passkey_complete"),
                                    {"credential": json.dumps(assertion)})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(int(self.client.session["_auth_user_id"]), self.user.pk)

    def test_passkey_login_satisfies_the_second_factor(self):
        begin = self.client.get(reverse("mfa:passkey_begin"))
        assertion = self.device.get(json.loads(begin.json()["options"]))
        self.client.post(reverse("mfa:passkey_complete"),
                         {"credential": json.dumps(assertion)})
        self.assertTrue(self.client.session["mfa"]["verified"])
        self.assertEqual(self.client.session["mfa"]["method"], "webauthn")

    def test_passkey_begin_produces_an_empty_allow_list(self):
        """The mechanism that makes login usernameless: an empty
        allowCredentials tells the browser/authenticator to offer any
        resident credential it holds for this RP, rather than restricting
        the prompt to one already-known user's credential(s).
        """
        begin = self.client.get(reverse("mfa:passkey_begin"))
        options = json.loads(begin.json()["options"])
        self.assertEqual(options["publicKey"].get("allowCredentials"), [])

    def test_passkey_begin_rejects_non_get(self):
        response = self.client.post(reverse("mfa:passkey_begin"))
        self.assertEqual(response.status_code, 405)

    def test_passkey_complete_rejects_non_post(self):
        response = self.client.get(reverse("mfa:passkey_complete"))
        self.assertEqual(response.status_code, 405)

    # -- Property 1: no account enumeration -----------------------------------

    def test_unknown_credential_does_not_reveal_account_existence(self):
        other = SoftwareAuthenticator(origin="https://testserver",
                                      rp_id="testserver")
        # Mint local key material only (no `user` in these options, so
        # other.user_handle stays None -- this authenticator was never
        # issued a handle for any account on this server, real or forged).
        other.create({"publicKey": {"challenge": "AAAA"}})
        begin = self.client.get(reverse("mfa:passkey_begin"))
        assertion = other.get(json.loads(begin.json()["options"]))
        response = self.client.post(reverse("mfa:passkey_complete"),
                                    {"credential": json.dumps(assertion)})
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("a@example.com", response.content.decode())

    def test_every_named_failure_mode_returns_a_byte_identical_response(self):
        """unknown handle, unknown credential, bad signature, missing
        state, and tampered payload must all be indistinguishable to the
        caller -- proven here by literal byte equality of the response
        bodies, not just "they're all 400s".
        """
        responses = {}

        # unknown handle: a device this server has never issued a handle to,
        # answering with no userHandle at all.
        stranger = SoftwareAuthenticator(origin="https://testserver",
                                         rp_id="testserver")
        stranger.create({"publicKey": {"challenge": "AAAA"}})
        begin = self.client.get(reverse("mfa:passkey_begin"))
        assertion = stranger.get(json.loads(begin.json()["options"]))
        responses["unknown handle"] = self.client.post(
            reverse("mfa:passkey_complete"), {"credential": json.dumps(assertion)})

        # unknown credential: a different physical device, but its assertion
        # is (falsely) tagged with this user's real handle.
        impostor = SoftwareAuthenticator(origin="https://testserver",
                                         rp_id="testserver")
        # mint local key material only
        impostor.create({"publicKey": {"challenge": "AAAA"}})
        begin = self.client.get(reverse("mfa:passkey_begin"))
        assertion = impostor.get(json.loads(begin.json()["options"]),
                                 user_handle=self._handle_bytes(self.user))
        responses["unknown credential"] = self.client.post(
            reverse("mfa:passkey_complete"), {"credential": json.dumps(assertion)})

        # bad signature: the enrolled device's own assertion, one byte of
        # the signature flipped.
        begin = self.client.get(reverse("mfa:passkey_begin"))
        assertion = self.device.get(json.loads(begin.json()["options"]))
        sig = assertion["response"]["signature"]
        assertion["response"]["signature"] = ("A" if sig[-1] != "A" else "B") + sig[1:]
        responses["bad signature"] = self.client.post(
            reverse("mfa:passkey_complete"), {"credential": json.dumps(assertion)})

        # missing state: a well-formed assertion, but the session ceremony
        # state was never established (no prior GET to passkey_begin here).
        begin = self.client.get(reverse("mfa:passkey_begin"))
        assertion = self.device.get(json.loads(begin.json()["options"]))
        session = self.client.session
        session.pop("webauthn_passkey_state", None)
        session.save()
        responses["missing state"] = self.client.post(
            reverse("mfa:passkey_complete"), {"credential": json.dumps(assertion)})

        # tampered payload: state is present and fresh, but `credential`
        # isn't valid JSON at all.
        self.client.get(reverse("mfa:passkey_begin"))
        responses["tampered payload"] = self.client.post(
            reverse("mfa:passkey_complete"), {"credential": "{not json"})

        for name, response in responses.items():
            self.assertEqual(response.status_code, 400, name)

        bodies = {name: r.content for name, r in responses.items()}
        distinct_bodies = set(bodies.values())
        self.assertEqual(len(distinct_bodies), 1, bodies)

        # None of these attempts logged anyone in, whichever branch failed.
        self.assertNotIn("_auth_user_id", self.client.session)

    # -- Property 3: a passkey for user A must never log in user B -----------

    def test_forged_user_handle_does_not_authenticate_as_the_claimed_user(self):
        """The signature and credential id genuinely belong to self.user's
        real enrolled device; only the userHandle field of the JSON payload
        is edited to claim a different account. complete_verify() scopes
        the allow-list to whichever user the (claimed) handle resolves to,
        so self.user's real credential id is simply absent from `victim`'s
        list -- proving a client cannot redirect a valid signature onto
        someone else's account just by editing the wire payload.
        """
        victim = User.objects.create_user("victim@example.com", password="pw")
        begin = self.client.get(reverse("mfa:passkey_begin"))
        assertion = self.device.get(json.loads(begin.json()["options"]))
        forged = urlsafe_b64encode(
            self._handle_bytes(victim)).rstrip(b"=").decode("ascii")
        assertion["response"]["userHandle"] = forged

        response = self.client.post(reverse("mfa:passkey_complete"),
                                    {"credential": json.dumps(assertion)})

        self.assertEqual(response.status_code, 400)
        self.assertNotIn("_auth_user_id", self.client.session)

    # -- Property 4: clone detection applies on the passwordless path too ----

    def test_regressed_sign_counter_is_rejected_on_the_passwordless_path(self):
        begin = self.client.get(reverse("mfa:passkey_begin"))
        assertion = self.device.get(json.loads(begin.json()["options"]))
        first = self.client.post(reverse("mfa:passkey_complete"),
                                 {"credential": json.dumps(assertion)})
        self.assertEqual(first.status_code, 302)
        self.client.logout()

        auth = Authenticator.objects.get(user=self.user, type="webauthn")
        auth.data["sign_count"] = 99
        auth.save()

        begin = self.client.get(reverse("mfa:passkey_begin"))
        # counter -> 2, still < 99
        assertion = self.device.get(json.loads(begin.json()["options"]))
        response = self.client.post(reverse("mfa:passkey_complete"),
                                    {"credential": json.dumps(assertion)})

        self.assertEqual(response.status_code, 400)
        self.assertNotIn("_auth_user_id", self.client.session)

    # -- Property 5: UV gates satisfying BOTH factors -------------------------

    def test_uv_assertion_marks_the_session_fully_verified(self):
        # SoftwareAuthenticator.get() always sets FLAG_UP | FLAG_UV (see its
        # docstring) -- this is the positive counterpart to
        # test_up_only_assertion_authenticates_but_leaves_second_factor_pending
        # below, confirming the UV flag is actually inspected in both
        # directions, not just one.
        begin = self.client.get(reverse("mfa:passkey_begin"))
        assertion = self.device.get(json.loads(begin.json()["options"]))
        self.client.post(reverse("mfa:passkey_complete"),
                         {"credential": json.dumps(assertion)})
        self.assertTrue(self.client.session["mfa"]["verified"])

    def test_up_only_assertion_authenticates_but_leaves_second_factor_pending(self):
        """The core of property 5: a UP-only (no PIN/biometric) assertion
        from the SAME enrolled device still logs the user in -- WebAuthn
        login only strictly requires User Present -- but must NOT be
        upgraded to "both factors satisfied". If this assertion fails,
        django_mfa is silently treating possession alone as equivalent to
        possession+verification.
        """
        up_only_device = _UpOnlyAuthenticator(origin="https://testserver",
                                              rp_id="testserver")
        up_only_device.private_key = self.device.private_key
        up_only_device.credential_id = self.device.credential_id
        up_only_device.sign_count = self.device.sign_count

        begin = self.client.get(reverse("mfa:passkey_begin"))
        assertion = up_only_device.get(json.loads(begin.json()["options"]),
                                       user_handle=self._handle_bytes(self.user))
        response = self.client.post(reverse("mfa:passkey_complete"),
                                    {"credential": json.dumps(assertion)})

        self.assertEqual(response.status_code, 302)
        self.assertEqual(int(self.client.session["_auth_user_id"]), self.user.pk)
        # Logged in, yes -- but NOT treated as having satisfied the second
        # factor. A pending (not verified) "mfa" session state means
        # MfaMiddleware will still challenge this user for a real second
        # factor before letting them reach anything non-exempt.
        self.assertFalse(self.client.session["mfa"]["verified"])

    # -- MFA_QUICKLOGIN rides on this same view; confirm it still works end
    #    to end when enabled (unit-level coverage lives in QuickLoginTests
    #    below).

    @override_settings(MFA_QUICKLOGIN=True)
    def test_quicklogin_hint_cookie_is_set_after_a_real_passkey_login(self):
        begin = self.client.get(reverse("mfa:passkey_begin"))
        assertion = self.device.get(json.loads(begin.json()["options"]))
        response = self.client.post(reverse("mfa:passkey_complete"),
                                    {"credential": json.dumps(assertion)})

        self.assertIn("mfa_quicklogin", response.cookies)
        from django_mfa.quicklogin import user_from_hint
        self.assertEqual(
            user_from_hint(response.cookies["mfa_quicklogin"].value), self.user)


@override_settings(
    MFA_FIDO2_RP_ID="testserver",
    ALLOWED_HOSTS=["testserver"],
    AUTHENTICATION_BACKENDS=["django_mfa.backends.WebAuthnBackend",
                             "django.contrib.auth.backends.ModelBackend"],
)
class UpOnlyPasskeySoleFactorRegressionTests(TestCase):
    """Task 19, part 4(b): an end-to-end regression pinning the full
    UP-only-passkey-as-sole-factor sequence, which until now has only been
    verified by reasoning (see the task-18/19 briefs) plus the isolated
    unit coverage in
    PasswordlessLoginTests.test_up_only_assertion_authenticates_but_leaves_second_factor_pending
    above. That test proves step 1 below in isolation; this test proves the
    other three pieces actually chain together for a user who has no
    fallback factor at all:

      1. Passwordless login with a User-Present-only (no PIN/biometric)
         assertion -- e.g. a security key with no PIN set up -- logs the
         user in but leaves "mfa" pending, exactly like a plain password
         login would (see adapters/webauthn.py + views/verify.py
         passkey_complete()).
      2. MfaMiddleware, seeing an authenticated-but-pending session,
         redirects any non-exempt request to the picker (mfa:verify).
      3. The picker (django_mfa/views/picker.py) sees exactly one enabled
         factor -- this same passkey, since it's this user's only one --
         and immediately redirects again to that factor's own verify page,
         rather than making a user with one factor choose from a list of
         one.
      4. Re-tapping the SAME physical key there (an ordinary second
         WebAuthn assertion, ``verify_factor``'s normal path) completes the
         second-factor challenge and clears the pending state, so the
         previously-blocked page becomes reachable.

    If any of steps 2-4 ever regressed -- e.g. the picker stopped
    auto-redirecting a lone WebAuthn factor, or verify_factor rejected a
    second assertion from an already-passkey-authenticated session -- a
    user in this position (no TOTP, no recovery codes, just the one
    passkey) would be locked in a redirect loop with no way to ever reach
    LOGIN_REDIRECT_URL. That is exactly the failure mode this test exists
    to catch.
    """

    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.device = SoftwareAuthenticator(origin="https://testserver",
                                            rp_id="testserver")
        self.client = Client()
        self._enroll()

    def _enroll(self):
        # Mirrors PasswordlessLoginTests._enroll(): the user's ONLY factor
        # is this one WebAuthn passkey -- no TOTP, no recovery codes, so
        # there is no fallback if the sequence below ever regresses into a
        # loop.
        self.client.login(username="a@example.com", password="pw")
        response = self.client.get(reverse("mfa:enroll_factor", args=["webauthn"]))
        options = json.loads(response.context["options"])
        credential = self.device.create(options)
        self.client.post(reverse("mfa:enroll_factor", args=["webauthn"]),
                         {"credential": json.dumps(credential), "name": "passkey"})
        self.client.logout()

    def test_up_only_passkey_login_reaches_full_verification_without_a_loop(self):
        # Step 1: passwordless login with a UP-only assertion from the
        # enrolled device. _UpOnlyAuthenticator is a distinct Python object
        # from self.device sharing the same key material (see
        # PasswordlessLoginTests.
        #   test_up_only_assertion_authenticates_but_leaves_second_factor_pending
        # above for why this class exists) -- its sign_count starts wherever
        # self.device's does and is copied back afterwards so the ordinary
        # get() in step 4 doesn't trip clone detection against a counter the
        # UP-only object already advanced.
        up_only_device = _UpOnlyAuthenticator(origin="https://testserver",
                                              rp_id="testserver")
        up_only_device.private_key = self.device.private_key
        up_only_device.credential_id = self.device.credential_id
        up_only_device.sign_count = self.device.sign_count

        begin = self.client.get(reverse("mfa:passkey_begin"))
        assertion = up_only_device.get(
            json.loads(begin.json()["options"]),
            user_handle=user_handle_for(self.user).encode("utf-8"))
        login_response = self.client.post(
            reverse("mfa:passkey_complete"), {"credential": json.dumps(assertion)})

        self.assertEqual(login_response.status_code, 302)
        self.assertEqual(int(self.client.session["_auth_user_id"]), self.user.pk)
        self.assertFalse(self.client.session["mfa"]["verified"])
        self.device.sign_count = up_only_device.sign_count

        # Step 2: the session is authenticated but pending -- any
        # non-exempt page redirects to the picker.
        blocked = self.client.get(reverse("mfa:security_settings"))
        self.assertEqual(blocked.status_code, 302)
        self.assertIn(reverse("mfa:verify"), blocked.url)

        # Step 3: the picker sees exactly one enabled factor (this same
        # passkey) and redirects straight to it.
        picker_response = self.client.get(reverse("mfa:verify"))
        self.assertRedirects(
            picker_response, reverse("mfa:verify_factor", args=["webauthn"]),
            fetch_redirect_response=False)

        verify_page = self.client.get(reverse("mfa:verify_factor", args=["webauthn"]))
        self.assertEqual(verify_page.status_code, 200)

        # Step 4: re-tapping the SAME physical key -- an ordinary WebAuthn
        # second-factor assertion, no different from any other
        # verify_factor round trip -- completes the challenge.
        options = json.loads(verify_page.context["options"])
        assertion = self.device.get(options)
        complete = self.client.post(
            reverse("mfa:verify_factor", args=["webauthn"]),
            {"credential": json.dumps(assertion)})

        self.assertEqual(complete.status_code, 302)
        self.assertTrue(self.client.session["mfa"]["verified"])
        self.assertEqual(self.client.session["mfa"]["method"], "webauthn")

        # The loop is broken: the page that redirected in step 2 is now
        # reachable.
        unblocked = self.client.get(reverse("mfa:security_settings"))
        self.assertEqual(unblocked.status_code, 200)


class QuickLoginTests(TestCase):
    """MFA_QUICKLOGIN: see the module docstring for why these drive a real
    request -> response cycle with RequestFactory + MfaMiddleware rather
    than django.test.Client.login().
    """

    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")

    def _login_response(self):
        request = RequestFactory().get("/", secure=True)
        request.session = SessionStore()
        auth_login(request, self.user,
                  backend="django.contrib.auth.backends.ModelBackend")
        response = HttpResponse()
        MfaMiddleware(lambda r: response).process_response(request, response)
        return response

    def test_default_is_off(self):
        self.assertFalse(mfa_settings.MFA_QUICKLOGIN)

    @override_settings(MFA_QUICKLOGIN=False)
    def test_disabled_by_default_leaves_no_hint_cookie(self):
        response = self._login_response()
        self.assertNotIn("mfa_quicklogin", response.cookies)

    @override_settings(MFA_QUICKLOGIN=True)
    def test_enabled_sets_a_signed_hint_cookie_on_login(self):
        response = self._login_response()
        self.assertIn("mfa_quicklogin", response.cookies)

    @override_settings(MFA_QUICKLOGIN=True)
    def test_hint_resolves_back_to_the_user(self):
        from django_mfa.quicklogin import user_from_hint

        response = self._login_response()
        value = response.cookies["mfa_quicklogin"].value
        self.assertEqual(user_from_hint(value), self.user)

    @override_settings(MFA_QUICKLOGIN=True)
    def test_tampered_hint_resolves_to_none(self):
        from django_mfa.quicklogin import user_from_hint

        self.assertIsNone(user_from_hint("garbage"))

    @override_settings(MFA_QUICKLOGIN=True)
    def test_hint_cookie_is_cleared_on_logout(self):
        from django.contrib.auth import logout as auth_logout

        request = RequestFactory().get("/", secure=True)
        request.session = SessionStore()
        auth_login(request, self.user,
                  backend="django.contrib.auth.backends.ModelBackend")
        request.user = self.user
        auth_logout(request)
        response = HttpResponse()
        MfaMiddleware(lambda r: response).process_response(request, response)
        self.assertEqual(response.cookies["mfa_quicklogin"].value, "")
        self.assertEqual(response.cookies["mfa_quicklogin"]["max-age"], 0)
