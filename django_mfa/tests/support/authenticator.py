"""In-process software WebAuthn authenticator for tests.

Mirrors what a real browser's ``navigator.credentials.create()`` /
``navigator.credentials.get()`` would produce and what ``webauthn.js`` would
POST to the server: base64url-encoded JSON payloads. This lets the tests in
later tasks drive real ``fido2.server.Fido2Server`` registration and
authentication ceremonies instead of a Python-only shortcut.

Built against the *installed* ``fido2`` version (2.2.1), which differs from
the 1.x API the original plan text was written against. See
``.superpowers/sdd/2026-08-12-mfa2-parity-foundation/task-14-report.md`` for
the full API diff.
"""
import hashlib
import json
import os
from base64 import urlsafe_b64decode, urlsafe_b64encode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from fido2 import cbor  # cbor2 is NOT installed; fido2 vendors its own
from fido2.cose import ES256
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

FLAG_UP = AuthenticatorData.FLAG.UP
FLAG_UV = AuthenticatorData.FLAG.UV
FLAG_AT = AuthenticatorData.FLAG.AT


def b64url(data):
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value):
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


class SoftwareAuthenticator:
    """An in-process WebAuthn authenticator for tests.

    Holds one EC P-256 key pair, assembles authenticator data using
    ``fido2.webauthn.AuthenticatorData.create``/``AttestedCredentialData.create``,
    and signs ``authData + SHA256(clientDataJSON)`` exactly as a real
    authenticator does. Preferred over recorded fixtures, which rot on
    library upgrades.
    """

    #: Sentinel distinguishing "no user_handle argument was passed at all"
    #: (default to whatever this authenticator remembers from create(), like
    #: a real resident/discoverable credential would) from an explicit
    #: `user_handle=None` (force no handle, e.g. to simulate an authenticator
    #: that was never issued one for any account). See create()/get() below.
    _UNSET = object()

    def __init__(self, origin, rp_id, aaguid=b"\x00" * 16):
        self.origin = origin
        self.rp_id = rp_id
        self.aaguid = aaguid
        self.sign_count = 0
        self.private_key = None
        self.credential_id = None
        #: The raw (decoded) user handle bytes this authenticator was
        #: issued at registration time, or None. A REAL authenticator
        #: creating a resident/discoverable credential stores the
        #: PublicKeyCredentialUserEntity.id it was given and echoes it back
        #: on every subsequent get() for that credential -- that's what
        #: makes usernameless/passwordless login possible at all, since the
        #: RP has no other way to know who's answering an empty
        #: allowCredentials challenge. Populated by create() below.
        self.user_handle = None

    def _client_data(self, type_, challenge):
        return json.dumps({
            "type": type_,
            "challenge": challenge,
            "origin": self.origin,
            "crossOrigin": False,
        }, separators=(",", ":")).encode("utf-8")

    def _rp_id_hash(self):
        return hashlib.sha256(self.rp_id.encode("utf-8")).digest()

    def create(self, options):
        """Mirror navigator.credentials.create()."""
        pk = options["publicKey"]
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)

        # Remember the user handle this credential was registered for, the
        # same way a real resident/discoverable credential's authenticator
        # would -- see the user_handle attribute's docstring in __init__.
        # `user` is optional here (some callers only want throwaway key
        # material and pass minimal options with no `user` at all), and its
        # `id` arrives as a base64url string (this is the raw, pre-JS
        # server-generated options shape -- see decodeOptions() in
        # webauthn.js for the browser-side equivalent of this decode).
        user_id = pk.get("user", {}).get("id")
        self.user_handle = _b64url_decode(user_id) if user_id else None

        cose_key = ES256.from_cryptography_key(self.private_key.public_key())
        credential_data = AttestedCredentialData.create(
            self.aaguid, self.credential_id, cose_key)

        auth_data = AuthenticatorData.create(
            self._rp_id_hash(),
            FLAG_UP | FLAG_UV | FLAG_AT,
            self.sign_count,
            credential_data,
        )
        client_data = self._client_data("webauthn.create", pk["challenge"])

        attestation_object = cbor.encode({
            "fmt": "none",
            "attStmt": {},
            "authData": bytes(auth_data),
        })

        result = {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "attestationObject": b64url(attestation_object),
            },
        }

        # Only echo a credProps result if the caller actually asked for the
        # extension (options["publicKey"]["extensions"]["credProps"]), mirroring
        # a real authenticator/browser, which never invents extension outputs
        # for extensions nobody requested. "rk" reflects the resident-key
        # policy the caller asked for via authenticatorSelection.residentKey --
        # this is a software fake with no real storage-mode distinction, so it
        # reports what it was asked to do rather than measuring anything.
        if pk.get("extensions", {}).get("credProps"):
            resident_key = pk.get("authenticatorSelection", {}).get("residentKey")
            result["clientExtensionResults"] = {
                "credProps": {"rk": resident_key in ("required", "preferred")},
            }

        return result

    def get(self, options, user_handle=_UNSET):
        """Mirror navigator.credentials.get().

        ``user_handle`` defaults to whatever this authenticator remembered
        from create() (see the user_handle attribute's docstring) rather
        than to a hardcoded None: a real discoverable-credential
        authenticator always supplies its own stored user handle when
        answering an empty-allowCredentials (usernameless) challenge,
        without the RP needing to ask for a specific one. Tests that need a
        specific -- or absent, or forged -- handle can still pass
        ``user_handle=`` explicitly to override this (including
        ``user_handle=None`` to force "no handle" even if create() set one).
        """
        if user_handle is self._UNSET:
            user_handle = self.user_handle
        pk = options["publicKey"]
        self.sign_count += 1
        auth_data = AuthenticatorData.create(
            self._rp_id_hash(),
            FLAG_UP | FLAG_UV,
            self.sign_count,
        )
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
