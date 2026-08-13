# django_mfa/adapters/webauthn.py
#
# WebAuthn (security key / passkey) adapter -- registration AND verification.
# Browser JS and passwordless login are later tasks; nothing here implements
# those.
#
# Written against the *installed* fido2 2.2.1, not the 1.x API the original
# task brief was drafted against. See
# .superpowers/sdd/2026-08-12-mfa2-parity-foundation/task-14-report.md,
# task-15-report.md and task-16-report.md for the verified 2.2.1 API map and
# every place this deviates from the brief's hypothesised calls.
import json

from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestedCredentialData,
    AuthenticationResponse,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
)

from django_mfa.atomic import update_data
from django_mfa.conf import settings as mfa_settings
from django_mfa.handles import user_handle_for
from django_mfa.models import Authenticator
from django_mfa.registry import Adapter

#: Session key the in-progress registration challenge/state is stashed under
#: between begin_enroll() and complete_enroll(). Popped (not just read) on
#: use so a completed -- or abandoned -- registration ceremony cannot be
#: replayed: see complete_enroll().
REGISTER_STATE_KEY = "webauthn_register_state"

#: Session key the in-progress authentication challenge/state is stashed
#: under between begin_verify() and complete_verify(). Popped (not just
#: read) on use for the same single-use reason as REGISTER_STATE_KEY -- see
#: complete_verify().
AUTH_STATE_KEY = "webauthn_auth_state"


def get_server():
    """Build a Fido2Server bound to the configured relying party.

    Constructed fresh per call (cheap: no I/O) rather than as a module-level
    singleton so it always reflects current settings, including in tests that
    use @override_settings(MFA_FIDO2_RP_ID=...).
    """
    rp = PublicKeyCredentialRpEntity(id=mfa_settings.MFA_FIDO2_RP_ID,
                                     name=mfa_settings.MFA_FIDO2_RP_NAME)
    return Fido2Server(rp, attestation=mfa_settings.MFA_FIDO2_ATTESTATION_PREFERENCE)


def user_entity(user):
    """Build the PublicKeyCredentialUserEntity for a ceremony.

    ``id`` is the signed, opaque user handle (django_mfa.handles), never the
    username or primary key directly -- see handles.py for why. Derived
    entirely from ``user``, which callers must obtain from ``request.user``,
    never from client-supplied data: this is what stops a caller from
    registering a credential against someone else's account.
    """
    return PublicKeyCredentialUserEntity(
        id=user_handle_for(user).encode("utf-8"),
        name=user.get_username(),
        display_name=user.get_username(),
    )


class WebAuthnAdapter(Adapter):
    type = Authenticator.Type.WEBAUTHN
    verbose_name = "Security key or passkey"
    supports_multiple = True

    def _existing_credentials(self, user):
        """AttestedCredentialData for every credential this user already holds.

        Dual purpose: passed to register_begin() as ``excludeCredentials`` so
        a compliant authenticator refuses to create a second resident
        credential for a device it has already enrolled (and so an existing
        credential continues to work under a different RP ID is impossible
        to fake -- registration binds to whatever RP the server was built
        with; see get_server()); and passed to authenticate_begin()/
        authenticate_complete() as the allow-list a verification ceremony is
        checked against -- see begin_verify()/complete_verify() below. Using
        the *same* per-user query for both means a credential can only ever
        be verified against the user it was actually enrolled to: a
        different user's request.user simply never sees it in this list.
        """
        return [
            AttestedCredentialData(bytes.fromhex(auth.data["credential_data"]))
            for auth in self.get_instances(user)
        ]

    def begin_enroll(self, request):
        server = get_server()
        options, state = server.register_begin(
            user_entity(request.user),
            self._existing_credentials(request.user),
            resident_key_requirement=mfa_settings.MFA_FIDO2_RESIDENT_KEY,
            user_verification=mfa_settings.MFA_FIDO2_USER_VERIFICATION,
            authenticator_attachment=mfa_settings.MFA_FIDO2_AUTHENTICATOR_ATTACHMENT,
            # Request the credProps extension so the client tells us, in
            # clientExtensionResults, whether the credential it created is
            # actually discoverable/resident. This is the only honest source
            # of that information -- see complete_enroll() below for why the
            # authenticatorData AT flag is NOT it. register_begin()'s
            # `extensions` parameter is a free-form Mapping[str, Any] in
            # fido2 2.2.1 (confirmed by reading PublicKeyCredentialCreationOptions
            # in fido2/webauthn.py), passed straight through with no
            # allowlist, so this is supported as-is.
            extensions={"credProps": True},
        )
        # dict(options) walks the CredentialCreationOptions dataclass into the
        # camelCase, base64url-string shape navigator.credentials.create()
        # expects, omitting any optional field left None. See task-14-report.md
        # API map item 7.
        request.session[REGISTER_STATE_KEY] = state
        return {"options": json.dumps(dict(options))}

    def complete_enroll(self, request, data):
        """Complete a registration ceremony started by begin_enroll().

        Note the deliberate asymmetry with complete_verify(): a missing/
        already-used challenge makes *this* method raise ValueError, but
        makes complete_verify() return False instead. Callers (views) must
        handle both conventions deliberately rather than assuming a single
        shared error-handling pattern works for both ceremonies.
        """
        # .pop(), not .get(): makes the challenge single-use. A second
        # complete_enroll() call -- whether a genuine replay of a captured
        # request or a double-submit -- finds nothing here and fails closed,
        # rather than re-validating (and accepting) the same signed
        # attestation twice.
        state = request.session.pop(REGISTER_STATE_KEY, None)
        if state is None:
            raise ValueError("Registration challenge missing or already used.")

        credential = json.loads(data["credential"])
        # register_complete() accepts the plain dict navigator.credentials
        # produces directly (internally calls RegistrationResponse.from_dict);
        # no need to construct that dataclass by hand. Raises ValueError on
        # any ceremony failure: wrong challenge, wrong origin, wrong RP ID
        # hash, bad/missing attestation signature, etc. -- so a credential
        # registered under one MFA_FIDO2_RP_ID cannot be completed against a
        # server configured with a different one.
        auth_data = get_server().register_complete(state, credential)

        # Resident/discoverable-ness must come from the credProps client
        # extension result, NOT from AuthenticatorData.FLAG.AT: that flag
        # means "attested credential data is present in this authData",
        # which is true on every single registration ceremony (it's what
        # carries the new credential ID/public key back to the server) --
        # it says nothing about whether the credential is stored as a
        # discoverable/resident credential. Using it as a resident indicator
        # would mark every credential resident, always, which is exactly the
        # bug this replaced. credProps is opt-in and not universally
        # supported by authenticators/browsers, so its absence is a real,
        # distinct outcome from "not resident" -- report it as None ("unknown")
        # rather than guessing True or False.
        client_extensions = credential.get("clientExtensionResults") or {}
        cred_props = client_extensions.get("credProps") or {}
        resident = cred_props.get("rk")  # True / False / None (unknown)

        return Authenticator.objects.create(
            user=request.user,
            type=self.type,
            name=data.get("name", "")[:100],
            data={
                "credential_id": auth_data.credential_data.credential_id.hex(),
                "credential_data": bytes(auth_data.credential_data).hex(),
                "sign_count": auth_data.counter,
                "resident": resident,
                "transports": credential.get("response", {}).get("transports", []),
            },
        )

    def _authenticator_for(self, user, credential_id):
        """Find the stored Authenticator row a verified assertion belongs to.

        Looked up by (user, credential_id) rather than credential_id alone:
        combined with credentials_for()/_existing_credentials() only ever
        handing authenticate_begin()/authenticate_complete() *this user's*
        credentials, a credential enrolled to a different user can never
        reach this point in the first place -- authenticate_complete()
        itself raises ValueError before we get here, because the assertion's
        credential id won't be found in the allow-list it was given. This is
        therefore a lookup, not an access-control check.
        """
        return self.get_instances(user).get(
            data__credential_id=credential_id.hex())

    def begin_verify(self, request, user):
        options, state = get_server().authenticate_begin(
            self._existing_credentials(user),
            user_verification=mfa_settings.MFA_FIDO2_USER_VERIFICATION,
        )
        request.session[AUTH_STATE_KEY] = state
        return {"options": json.dumps(dict(options))}

    def complete_verify(self, request, user, data):
        """Complete a verification ceremony started by begin_verify().

        Note the deliberate asymmetry with complete_enroll(): a missing/
        already-used challenge makes complete_enroll() raise ValueError, but
        makes this method return False instead (see the brief's own
        test_missing_state_is_rejected, which pins this exact behaviour).
        Callers (views) must handle both conventions -- a False return here
        does not mean "no exception was possible", it means "this specific,
        expected failure mode returns a sentinel instead of raising." A
        cloned-credential rejection still raises ValueError; a credential
        that vanished mid-ceremony (see below) also returns False, by
        design, for the same reason as the missing-state case: both are
        "this assertion cannot be honoured", not "something is broken."
        """
        # .pop(), not .get(): same single-use reasoning as complete_enroll().
        state = request.session.pop(AUTH_STATE_KEY, None)
        if state is None:
            return False

        credential = json.loads(data["credential"])
        # authenticate_complete() accepts the plain dict navigator.credentials
        # produces directly. In fido2 2.2.1 it returns the SAME
        # AttestedCredentialData object that was passed in via `credentials`,
        # matched by id -- not a freshly parsed object, and NOT something
        # carrying the new sign count (there is no `.new_sign_count` in this
        # version; see task-14-report.md API map item 4). Raises ValueError
        # on any ceremony failure: wrong challenge, wrong origin, bad/missing
        # signature, or (crucially) a credential id not present in the
        # `credentials` list we handed it -- which is how an assertion for a
        # credential enrolled to a different user gets rejected, since
        # _existing_credentials(user) only ever contains this user's own
        # credentials.
        result = get_server().authenticate_complete(
            state, self._existing_credentials(user), credential)

        try:
            auth = self._authenticator_for(user, result.credential_id)
        except Authenticator.DoesNotExist:
            # Race: the credential row was deleted in the window between
            # the server accepting the assertion (authenticate_complete,
            # above -- which validated against a snapshot of
            # _existing_credentials(user) taken at the top of this method)
            # and this lookup running -- e.g. the user removed this
            # security key from another tab/device while this login was in
            # flight. There is no row left to update a counter on and
            # nothing left to attribute a clone-check outcome to, so the
            # assertion is refused the same way a missing/expired session
            # state is refused above: return False rather than let
            # Authenticator.DoesNotExist propagate as an unhandled 500.
            # This is deliberately narrow -- only DoesNotExist is caught
            # here; a ValueError from the clone-detection check below must
            # still propagate unchanged, since that is a distinct,
            # deliberate "reject this" signal, not a missing-row race.
            return False
        # The return value of authenticate_complete() carries no counter at
        # all in fido2 2.2.1, so the new counter has to be recovered
        # independently by re-parsing the same response the client sent.
        # Confirmed empirically (task-14-report.md) that this equals the
        # authenticator's own idea of its counter.
        new_count = AuthenticationResponse.from_dict(
            credential).response.authenticator_data.counter

        def advance(current):
            """Clone-check against the committed counter, then advance it.

            Runs inside the compare-and-set rather than before it, and for
            the same reason clone detection exists at all: two racing
            assertions from a cloned credential would otherwise both read the
            pre-advance counter, both clear the check below, and the loser's
            write would drag the stored counter *backwards* -- leaving the
            clone undetected and every subsequent replay looking fresh.
            """
            stored = current.get("sign_count", 0)
            # Clone detection: a signature counter that fails to advance
            # suggests the authenticator (or its key material) has been
            # cloned and a second device is replaying/racing assertions. But
            # counters are OPTIONAL in the WebAuthn spec -- many
            # authenticators (notably Apple/iCloud passkeys) never implement
            # one and always report 0. Treat "both stored and new are 0" as
            # the legitimate counter-less case and accept it
            # unconditionally; for every other case, the new counter must be
            # strictly greater than the stored one or this assertion is
            # rejected as a possible clone. Do NOT simplify this to a plain
            # "new > stored" check -- that would lock out every user of a
            # counter-less authenticator, which today is a very large share
            # of them.
            #
            # Raising (rather than returning None to decline) is deliberate:
            # it propagates straight out of update_data() without retrying,
            # keeping "this is a clone" a distinct, loud signal from "this
            # assertion simply could not be honoured".
            if not (new_count == 0 and stored == 0) and new_count <= stored:
                raise ValueError("Authenticator sign count did not increase.")
            return {**current, "sign_count": new_count}

        if not update_data(auth, advance):
            return False
        auth.record_usage()
        return True
