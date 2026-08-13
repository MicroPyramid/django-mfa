import json
from base64 import urlsafe_b64decode
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import RequestFactory, TestCase, override_settings
from fido2.server import Fido2Server

import django_mfa.adapters.webauthn as webauthn_mod
from django_mfa.adapters.webauthn import WebAuthnAdapter
from django_mfa.handles import user_from_handle
from django_mfa.models import Authenticator
from django_mfa.tests.support.authenticator import SoftwareAuthenticator


def _b64url_decode(value):
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


@override_settings(MFA_FIDO2_RP_ID="testserver", ALLOWED_HOSTS=["testserver"])
class WebAuthnEnrollTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.adapter = WebAuthnAdapter()
        self.device = SoftwareAuthenticator(origin="https://testserver",
                                            rp_id="testserver")
        self.request = RequestFactory().get("/", secure=True)
        self.request.user = self.user
        self.request.session = {}

    def test_begin_enroll_stashes_state_server_side(self):
        ctx = self.adapter.begin_enroll(self.request)
        self.assertIn("options", ctx)
        self.assertIn("webauthn_register_state", self.request.session)

    def test_complete_enroll_stores_credential(self):
        ctx = self.adapter.begin_enroll(self.request)
        credential = self.device.create(json.loads(ctx["options"]))

        auth = self.adapter.complete_enroll(
            self.request,
            {"credential": json.dumps(credential), "name": "YubiKey 5C"})

        self.assertEqual(auth.type, Authenticator.Type.WEBAUTHN)
        self.assertEqual(auth.name, "YubiKey 5C")
        self.assertIn("credential_id", auth.data)
        self.assertEqual(auth.data["sign_count"], 0)

    def test_state_is_single_use(self):
        ctx = self.adapter.begin_enroll(self.request)
        credential = self.device.create(json.loads(ctx["options"]))
        self.adapter.complete_enroll(
            self.request, {"credential": json.dumps(credential), "name": "k"})
        with self.assertRaises(ValueError):
            self.adapter.complete_enroll(
                self.request, {"credential": json.dumps(credential), "name": "k"})

    def test_replaying_the_same_completed_registration_fails(self):
        """A captured, already-consumed registration request must not be
        repeatable -- proves the session-state pop is actually load-bearing
        and not just decoration around a check that would pass anyway.
        """
        ctx = self.adapter.begin_enroll(self.request)
        credential = self.device.create(json.loads(ctx["options"]))
        payload = {"credential": json.dumps(credential), "name": "k"}

        self.adapter.complete_enroll(self.request, payload)
        self.assertEqual(self.user.mfa_authenticators.count(), 1)

        with self.assertRaises(ValueError):
            self.adapter.complete_enroll(self.request, payload)
        # The replay must not have created a second row.
        self.assertEqual(self.user.mfa_authenticators.count(), 1)

    def test_multiple_credentials_allowed(self):
        for name in ("key 1", "key 2"):
            ctx = self.adapter.begin_enroll(self.request)
            device = SoftwareAuthenticator(origin="https://testserver",
                                           rp_id="testserver")
            credential = device.create(json.loads(ctx["options"]))
            self.adapter.complete_enroll(
                self.request,
                {"credential": json.dumps(credential), "name": name})
        self.assertEqual(self.user.mfa_authenticators.count(), 2)

    def test_exclude_credentials_populated_from_existing_credentials(self):
        """A second begin_enroll() must list the first credential in
        excludeCredentials, so a compliant authenticator can refuse to
        double-register the same physical key.
        """
        ctx = self.adapter.begin_enroll(self.request)
        credential = self.device.create(json.loads(ctx["options"]))
        self.adapter.complete_enroll(
            self.request, {"credential": json.dumps(credential), "name": "k1"})

        ctx2 = self.adapter.begin_enroll(self.request)
        options2 = json.loads(ctx2["options"])
        exclude_ids = [c["id"] for c in options2["publicKey"]["excludeCredentials"]]
        self.assertIn(credential["id"], exclude_ids)

    def test_begin_enroll_uses_authenticated_users_handle_not_client_input(self):
        """The user entity handed to the authenticator must be derived from
        request.user, never from anything the client could supply. Proven by
        decoding the handle embedded in the registration options and
        confirming it resolves back to the authenticated user.
        """
        ctx = self.adapter.begin_enroll(self.request)
        options = json.loads(ctx["options"])
        raw_handle = _b64url_decode(options["publicKey"]["user"]["id"]).decode("utf-8")
        self.assertEqual(user_from_handle(raw_handle), self.user)

    def test_credential_is_bound_to_authenticated_user_not_client_input(self):
        """Even if the caller stuffs extra, attacker-controlled keys into the
        completion payload (e.g. trying to claim another user's identity),
        the stored credential must still belong to request.user, because
        complete_enroll() never reads a user identifier out of `data`.
        """
        victim = User.objects.create_user("victim@example.com", password="pw")
        ctx = self.adapter.begin_enroll(self.request)
        credential = self.device.create(json.loads(ctx["options"]))

        auth = self.adapter.complete_enroll(
            self.request,
            {"credential": json.dumps(credential), "name": "k",
             "user_id": victim.pk, "user": victim.get_username(),
             "username": victim.get_username()})

        self.assertEqual(auth.user, self.user)
        self.assertEqual(victim.mfa_authenticators.count(), 0)

    def test_registration_rejects_credential_created_under_a_different_rp_id(self):
        """A credential whose authenticator signed for a different RP ID must
        be rejected by complete_enroll() -- proves registration is actually
        bound to MFA_FIDO2_RP_ID rather than trusting whatever the client
        happens to send.
        """
        ctx = self.adapter.begin_enroll(self.request)
        wrong_rp_device = SoftwareAuthenticator(origin="https://testserver",
                                                 rp_id="not-testserver")
        credential = wrong_rp_device.create(json.loads(ctx["options"]))

        with self.assertRaises(ValueError):
            self.adapter.complete_enroll(
                self.request, {"credential": json.dumps(credential), "name": "k"})
        self.assertEqual(self.user.mfa_authenticators.count(), 0)


@override_settings(MFA_FIDO2_RP_ID="testserver", ALLOWED_HOSTS=["testserver"])
class WebAuthnResidentKeyTests(TestCase):
    """`resident` must come from the credProps extension result, not from
    AuthenticatorData.FLAG.AT (which is set on every registration and is not
    a resident-key indicator at all -- see the comment in complete_enroll()).
    """

    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.adapter = WebAuthnAdapter()
        self.request = RequestFactory().get("/", secure=True)
        self.request.user = self.user
        self.request.session = {}

    def test_resident_is_true_when_authenticator_reports_rk_true(self):
        # MFA_FIDO2_RESIDENT_KEY defaults to "preferred", which
        # SoftwareAuthenticator.create() reflects back as rk: True.
        device = SoftwareAuthenticator(origin="https://testserver", rp_id="testserver")
        ctx = self.adapter.begin_enroll(self.request)
        credential = device.create(json.loads(ctx["options"]))

        auth = self.adapter.complete_enroll(
            self.request, {"credential": json.dumps(credential), "name": "k"})

        self.assertIs(auth.data["resident"], True)

    @override_settings(MFA_FIDO2_RESIDENT_KEY="discouraged")
    def test_resident_is_false_when_authenticator_reports_rk_false(self):
        device = SoftwareAuthenticator(origin="https://testserver", rp_id="testserver")
        ctx = self.adapter.begin_enroll(self.request)
        credential = device.create(json.loads(ctx["options"]))

        auth = self.adapter.complete_enroll(
            self.request, {"credential": json.dumps(credential), "name": "k"})

        self.assertIs(auth.data["resident"], False)

    def test_resident_is_none_when_extension_result_is_absent(self):
        """An authenticator/browser that doesn't support credProps returns no
        clientExtensionResults for it at all. That must be stored as
        ``None`` ("unknown"), never guessed as True or False.
        """
        device = SoftwareAuthenticator(origin="https://testserver", rp_id="testserver")
        ctx = self.adapter.begin_enroll(self.request)
        credential = device.create(json.loads(ctx["options"]))
        del credential["clientExtensionResults"]  # simulate no extension support

        auth = self.adapter.complete_enroll(
            self.request, {"credential": json.dumps(credential), "name": "k"})

        self.assertIsNone(auth.data["resident"])

    def test_begin_enroll_requests_the_credprops_extension(self):
        ctx = self.adapter.begin_enroll(self.request)
        options = json.loads(ctx["options"])
        self.assertEqual(options["publicKey"]["extensions"], {"credProps": True})


class _CounterlessAuthenticator(SoftwareAuthenticator):
    """Stands in for authenticators that never implement a signature
    counter -- notably Apple/iCloud passkeys -- which always report 0.

    ``sign_count`` is pinned to 0 via a property whose setter no-ops, rather
    than by reimplementing ``get()``: ``SoftwareAuthenticator.get()`` does
    ``self.sign_count += 1`` then bakes the (post-increment) value into the
    signed authenticator data. With the setter silently discarding that
    write, the read half of ``+=`` -- and everything downstream that reads
    ``self.sign_count`` -- always sees 0, so the produced assertion's own
    counter is genuinely 0, not just faked after the fact.
    """

    @property
    def sign_count(self):
        return 0

    @sign_count.setter
    def sign_count(self, value):
        pass


@override_settings(MFA_FIDO2_RP_ID="testserver", ALLOWED_HOSTS=["testserver"])
class WebAuthnVerifyTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.adapter = WebAuthnAdapter()
        self.device = SoftwareAuthenticator(origin="https://testserver",
                                            rp_id="testserver")
        self.request = RequestFactory().get("/", secure=True)
        self.request.user = self.user
        self.request.session = {}

        ctx = self.adapter.begin_enroll(self.request)
        credential = self.device.create(json.loads(ctx["options"]))
        self.auth = self.adapter.complete_enroll(
            self.request, {"credential": json.dumps(credential), "name": "k"})

    def _assert(self):
        ctx = self.adapter.begin_verify(self.request, self.user)
        return json.dumps(self.device.get(json.loads(ctx["options"])))

    def test_valid_assertion_verifies(self):
        self.assertTrue(self.adapter.complete_verify(
            self.request, self.user, {"credential": self._assert()}))

    def test_sign_count_is_persisted(self):
        self.adapter.complete_verify(
            self.request, self.user, {"credential": self._assert()})
        self.auth.refresh_from_db()
        self.assertEqual(self.auth.data["sign_count"], 1)

    def test_replayed_sign_count_is_rejected_as_a_clone(self):
        self.adapter.complete_verify(
            self.request, self.user, {"credential": self._assert()})
        self.auth.refresh_from_db()
        self.auth.data["sign_count"] = 99
        self.auth.save()

        with self.assertRaises(ValueError):
            self.adapter.complete_verify(
                self.request, self.user, {"credential": self._assert()})

    def test_missing_state_is_rejected(self):
        assertion = self._assert()
        self.request.session.pop("webauthn_auth_state", None)
        self.assertFalse(self.adapter.complete_verify(
            self.request, self.user, {"credential": assertion}))

    def test_counterless_authenticator_is_accepted_every_time(self):
        """The core anti-lockout guarantee: an authenticator that always
        reports sign_count 0 (e.g. an Apple/iCloud passkey) must keep
        verifying successfully across repeated logins, not just once. An
        over-strict "new > stored" implementation would accept the first
        0->0 assertion (0 stored as the enrollment baseline) but reject
        every subsequent one, since 0 is never > 0.
        """
        device = _CounterlessAuthenticator(origin="https://testserver",
                                           rp_id="testserver")
        ctx = self.adapter.begin_enroll(self.request)
        credential = device.create(json.loads(ctx["options"]))
        auth = self.adapter.complete_enroll(
            self.request, {"credential": json.dumps(credential), "name": "cl"})
        self.assertEqual(auth.data["sign_count"], 0)

        for _ in range(3):
            ctx = self.adapter.begin_verify(self.request, self.user)
            assertion = json.dumps(device.get(json.loads(ctx["options"])))
            self.assertTrue(self.adapter.complete_verify(
                self.request, self.user, {"credential": assertion}))
            auth.refresh_from_db()
            self.assertEqual(auth.data["sign_count"], 0)

    def test_assertion_for_a_different_users_credential_is_rejected(self):
        """A credential enrolled to one user must not verify a login for a
        different user, even if that credential produces a cryptographically
        valid assertion for the challenge it was handed -- proves
        begin_verify()/complete_verify() actually scope the allow-list to
        request.user's own credentials rather than trusting whatever
        credential id the client claims.
        """
        other_user = User.objects.create_user("b@example.com", password="pw")
        other_device = SoftwareAuthenticator(origin="https://testserver",
                                             rp_id="testserver")
        other_request = RequestFactory().get("/", secure=True)
        other_request.user = other_user
        other_request.session = {}
        ctx = self.adapter.begin_enroll(other_request)
        credential = other_device.create(json.loads(ctx["options"]))
        self.adapter.complete_enroll(
            other_request, {"credential": json.dumps(credential), "name": "k2"})

        # other_user's own device answers a challenge issued for self.user.
        ctx = self.adapter.begin_verify(self.request, self.user)
        assertion = json.dumps(other_device.get(json.loads(ctx["options"])))

        with self.assertRaises(ValueError):
            self.adapter.complete_verify(
                self.request, self.user, {"credential": assertion})

    def test_record_usage_is_called_on_success(self):
        self.assertIsNone(self.auth.last_used_at)
        self.adapter.complete_verify(
            self.request, self.user, {"credential": self._assert()})
        self.auth.refresh_from_db()
        self.assertIsNotNone(self.auth.last_used_at)

    def test_credential_deleted_mid_ceremony_is_rejected_not_raised(self):
        """Reproduces the race: the credential row is deleted in the window
        between authenticate_complete() accepting the assertion and
        _authenticator_for()'s .get() loading the row to update it -- e.g.
        the user removed this security key from another tab/device while
        this login was in flight.

        This is NOT reachable by simply deleting the row before calling
        complete_verify(): _existing_credentials(user) is re-queried at the
        top of complete_verify(), so a deletion that happens before that
        call is already excluded from the allow-list handed to
        authenticate_complete(), which then rejects the assertion itself
        with ValueError (unknown credential) -- a different, earlier path,
        already covered by test_assertion_for_a_different_users_credential_is_rejected's
        sibling scenario. To land inside the actual race window (*between*
        authenticate_complete() returning and the next line running) this
        patches Fido2Server.authenticate_complete to delete the row
        immediately after delegating to the real implementation, so the
        deletion happens exactly once the server has already accepted the
        assertion but before complete_verify() reaches _authenticator_for().
        """
        assertion = self._assert()
        real_authenticate_complete = Fido2Server.authenticate_complete

        def delete_credential_then_return(self_server, *args, **kwargs):
            result = real_authenticate_complete(self_server, *args, **kwargs)
            Authenticator.objects.filter(pk=self.auth.pk).delete()
            return result

        with patch.object(Fido2Server, "authenticate_complete",
                          delete_credential_then_return):
            verified = self.adapter.complete_verify(
                self.request, self.user, {"credential": assertion})

        self.assertFalse(verified)
        self.assertFalse(Authenticator.objects.filter(pk=self.auth.pk).exists())


@override_settings(MFA_FIDO2_RP_ID="testserver", ALLOWED_HOSTS=["testserver"])
class WebAuthnSignCountConcurrencyTests(TestCase):
    """Clone detection is only as good as the counter it compares against.

    The stored sign count was read, checked, and written back as a plain
    read-modify-write. Two racing assertions from a cloned credential both
    read the pre-advance counter, both clear the "must increase" check, and
    the loser's write drags the stored counter backwards -- so the clone the
    check exists to catch goes undetected.
    """

    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.adapter = WebAuthnAdapter()
        self.device = SoftwareAuthenticator(origin="https://testserver",
                                            rp_id="testserver")
        self.request = RequestFactory().get("/", secure=True)
        self.request.user = self.user
        self.request.session = {}
        ctx = self.adapter.begin_enroll(self.request)
        credential = self.device.create(json.loads(ctx["options"]))
        self.auth = self.adapter.complete_enroll(
            self.request, {"credential": json.dumps(credential), "name": "k"})

    def _assert(self):
        ctx = self.adapter.begin_verify(self.request, self.user)
        return json.dumps(self.device.get(json.loads(ctx["options"])))

    def test_a_counter_advanced_mid_verification_is_not_regressed(self):
        assertion = self._assert()  # carries sign count 1
        fired = []
        real = webauthn_mod.AuthenticationResponse

        class Interfering:
            @staticmethod
            def from_dict(payload, _auth=self.auth):
                # Fire once, after complete_verify() has read the stored
                # counter but before it writes: a concurrent assertion lands
                # and advances the counter well past this one.
                if not fired:
                    fired.append(True)
                    Authenticator.objects.filter(pk=_auth.pk).update(
                        data={**_auth.data, "sign_count": 5})
                return real.from_dict(payload)

        with patch.object(webauthn_mod, "AuthenticationResponse", Interfering):
            with self.assertRaises(ValueError):
                self.adapter.complete_verify(
                    self.request, self.user, {"credential": assertion})

        self.assertTrue(fired, "the interleaving never happened")
        self.auth.refresh_from_db()
        self.assertEqual(self.auth.data["sign_count"], 5)
