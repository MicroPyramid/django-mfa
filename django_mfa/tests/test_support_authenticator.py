import base64

from django.test import TestCase
from fido2.server import Fido2Server
from fido2.webauthn import (
    AuthenticationResponse,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
)

from django_mfa.tests.support.authenticator import SoftwareAuthenticator, b64url


def _flip_byte(b64url_str):
    """Corrupt one byte of a base64url-encoded field, re-encoded the same way."""
    raw = bytearray(base64.urlsafe_b64decode(b64url_str + "=="))
    raw[0] ^= 0xFF
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")


class SoftwareAuthenticatorTests(TestCase):
    def setUp(self):
        self.authenticator = SoftwareAuthenticator(origin="https://example.com",
                                                   rp_id="example.com")

    def test_create_returns_attestation_payload(self):
        options = {"publicKey": {
            "challenge": "Y2hhbGxlbmdl",
            "rp": {"id": "example.com", "name": "test"},
            "user": {"id": "dXNlcg", "name": "a@example.com",
                     "displayName": "a@example.com"},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        }}
        result = self.authenticator.create(options)
        self.assertIn("id", result)
        self.assertIn("attestationObject", result["response"])
        self.assertIn("clientDataJSON", result["response"])

    def test_get_returns_assertion_signed_by_the_created_credential(self):
        create_options = {"publicKey": {
            "challenge": "Y2hhbGxlbmdl",
            "rp": {"id": "example.com", "name": "test"},
            "user": {"id": "dXNlcg", "name": "a@example.com",
                     "displayName": "a@example.com"},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        }}
        created = self.authenticator.create(create_options)

        assertion = self.authenticator.get({"publicKey": {
            "challenge": "YW5vdGhlcg",
            "rpId": "example.com",
            "allowCredentials": [{"type": "public-key", "id": created["id"]}],
        }})
        self.assertEqual(assertion["id"], created["id"])
        self.assertIn("signature", assertion["response"])

    def test_sign_count_increments_across_assertions(self):
        create_options = {"publicKey": {
            "challenge": "Y2hhbGxlbmdl",
            "rp": {"id": "example.com", "name": "test"},
            "user": {"id": "dXNlcg", "name": "a", "displayName": "a"},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        }}
        self.authenticator.create(create_options)
        self.assertEqual(self.authenticator.sign_count, 0)
        self.authenticator.get({"publicKey": {
            "challenge": "YQ", "rpId": "example.com"}})
        self.assertEqual(self.authenticator.sign_count, 1)


class SoftwareAuthenticatorInteropTests(TestCase):
    """Prove the harness actually satisfies a REAL Fido2Server, not just its
    own structural assertions above.

    Fix round 1 (task-14 review): a reviewer mutated ``get()`` to return a
    fixed bogus signature and the structural tests kept passing -- nothing
    in the committed suite exercised real signature verification. Tasks
    15-18 test WebAuthn registration, clone detection, and passwordless
    login entirely through this harness, so if it silently stops enforcing
    real cryptography, those tasks' tests would report green while testing
    nothing. These tests close that gap by driving a real
    ``fido2.server.Fido2Server`` through full registration/authentication
    ceremonies and asserting it both accepts genuine assertions and REJECTS
    forged ones.
    """

    def setUp(self):
        self.origin = "https://example.com"
        self.rp_id = "example.com"
        self.server = Fido2Server(
            PublicKeyCredentialRpEntity(id=self.rp_id, name="Example"))
        self.authenticator = SoftwareAuthenticator(
            origin=self.origin, rp_id=self.rp_id)
        self.user = PublicKeyCredentialUserEntity(
            id=b"user-1", name="a@example.com", display_name="a@example.com")

    def _register(self, authenticator, user):
        creation_options, state = self.server.register_begin(user)
        create_result = authenticator.create(dict(creation_options))
        auth_data = self.server.register_complete(state, create_result)
        return auth_data.credential_data

    def test_registration_round_trip_against_real_server(self):
        credential = self._register(self.authenticator, self.user)

        # The server accepted the attestation and handed back credential
        # data that actually corresponds to the authenticator's key.
        self.assertEqual(credential.credential_id, self.authenticator.credential_id)
        self.assertEqual(credential.public_key[3], -7)  # COSE alg: ES256

    def test_authentication_round_trip_against_real_server(self):
        credential = self._register(self.authenticator, self.user)

        request_options, auth_state = self.server.authenticate_begin([credential])
        get_result = self.authenticator.get(dict(request_options))
        result = self.server.authenticate_complete(
            auth_state, [credential], get_result)

        self.assertEqual(result.credential_id, credential.credential_id)

    def test_tampered_signature_is_rejected(self):
        credential = self._register(self.authenticator, self.user)
        request_options, auth_state = self.server.authenticate_begin([credential])
        get_result = self.authenticator.get(dict(request_options))

        forged = dict(get_result)
        forged["response"] = dict(get_result["response"])
        forged["response"]["signature"] = _flip_byte(
            get_result["response"]["signature"])

        with self.assertRaises(ValueError):
            self.server.authenticate_complete(auth_state, [credential], forged)

    def test_mismatched_challenge_is_rejected(self):
        credential = self._register(self.authenticator, self.user)

        # The real state the server is expecting a response for...
        _request_options, auth_state = self.server.authenticate_begin([credential])
        # ...but the assertion was actually produced for a DIFFERENT
        # (earlier/stale) challenge -- e.g. a replayed response.
        stale_options, _stale_state = self.server.authenticate_begin([credential])
        stale_get_result = self.authenticator.get(dict(stale_options))

        with self.assertRaises(ValueError):
            self.server.authenticate_complete(
                auth_state, [credential], stale_get_result)

    def test_assertion_signed_by_a_different_credentials_key_is_rejected(self):
        credential_a = self._register(self.authenticator, self.user)

        other_authenticator = SoftwareAuthenticator(
            origin=self.origin, rp_id=self.rp_id)
        other_user = PublicKeyCredentialUserEntity(
            id=b"user-2", name="b@example.com", display_name="b@example.com")
        credential_b = self._register(other_authenticator, other_user)

        request_options, auth_state = self.server.authenticate_begin(
            [credential_a, credential_b])

        # other_authenticator signs the CORRECT challenge with ITS OWN key,
        # then the response is relabelled to claim it came from
        # credential_a -- i.e. someone who controls credential_b tries to
        # pass their signature off as proof of possessing credential_a. The
        # server looks credential_a up by id and must reject the signature
        # because it doesn't verify under credential_a's public key.
        genuine = other_authenticator.get(dict(request_options))
        forged_id = b64url(credential_a.credential_id)
        forged = dict(genuine)
        forged["id"] = forged_id
        forged["rawId"] = forged_id

        with self.assertRaises(ValueError):
            self.server.authenticate_complete(
                auth_state, [credential_a, credential_b], forged)

    def test_counter_matches_authenticator_state_and_increases(self):
        credential = self._register(self.authenticator, self.user)
        self.assertEqual(self.authenticator.sign_count, 0)

        request_options, auth_state = self.server.authenticate_begin([credential])
        get_result = self.authenticator.get(dict(request_options))
        self.server.authenticate_complete(auth_state, [credential], get_result)

        first_counter = AuthenticationResponse.from_dict(
            get_result).response.authenticator_data.counter
        self.assertEqual(first_counter, self.authenticator.sign_count)
        self.assertEqual(first_counter, 1)

        request_options2, auth_state2 = self.server.authenticate_begin([credential])
        get_result2 = self.authenticator.get(dict(request_options2))
        self.server.authenticate_complete(auth_state2, [credential], get_result2)

        second_counter = AuthenticationResponse.from_dict(
            get_result2).response.authenticator_data.counter
        self.assertEqual(second_counter, self.authenticator.sign_count)
        self.assertGreater(second_counter, first_counter)
