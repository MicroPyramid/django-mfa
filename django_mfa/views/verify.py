import hashlib
import json

from django.conf import settings
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponseNotAllowed, JsonResponse
from django.shortcuts import redirect, render, resolve_url
from django.utils.http import url_has_allowed_host_and_scheme

from fido2.webauthn import AuthenticationResponse

from django_mfa import ratelimit, session
from django_mfa.adapters.webauthn import AUTH_STATE_KEY, WebAuthnAdapter, get_server
from django_mfa.backends import WebAuthnBackend, user_from_handle
from django_mfa.conf import settings as mfa_settings
from django_mfa.crypto import decrypt
from django_mfa.models import Authenticator
from django_mfa.registry import registry

GENERIC_ERROR = "Your code is expired or invalid."

#: Session key the in-progress *passwordless* authentication
#: challenge/state is stashed under between passkey_begin() and
#: passkey_complete(). Deliberately separate from
#: django_mfa.adapters.webauthn.AUTH_STATE_KEY -- that key belongs to a
#: ceremony scoped to an already-known, already-authenticated request.user
#: (the second-factor picker flow); this one is scoped to no user at all
#: (an anonymous visitor on the login page). Keeping them distinct means a
#: passwordless ceremony can never be finished against state meant for a
#: logged-in user's second-factor challenge, or vice versa.
PASSKEY_STATE_KEY = "webauthn_passkey_state"


def _passkey_failure():
    """The one and only response returned by passkey_complete() for every
    failure mode -- unknown handle, unknown credential, bad signature,
    missing/expired state, tampered payload, clone-detected sign counter.

    Deliberately generic and byte-for-byte identical across all of them
    (same status code, same body, constructed the same way every time): see
    passkey_complete()'s docstring for why. A fresh JsonResponse is built on
    every call rather than a module-level singleton being reused, since a
    response object is mutated as it's rendered/sent and must not be shared
    across requests.
    """
    return JsonResponse({"error": "Passkey sign-in failed."}, status=400)


def _adapter_or_404(factor_type):
    try:
        return registry.get(factor_type)
    except KeyError:
        raise Http404(f"Unknown factor {factor_type!r}")


def _safe_next(request):
    candidate = request.POST.get("next") or request.GET.get("next")
    if candidate and url_has_allowed_host_and_scheme(
        candidate, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return candidate
    return resolve_url(settings.LOGIN_REDIRECT_URL)


@login_required
def verify_factor(request, factor_type):
    adapter = _adapter_or_404(factor_type)
    next_url = _safe_next(request)
    context = {"adapter": adapter, "next": next_url,
               "base_template": mfa_settings.MFA_BASE_TEMPLATE}

    # The user_logged_in signal (signals.py:stamp_pending_verification)
    # already stamps the session pending as soon as a user who HAS a primary
    # factor logs in. For any session that reaches this view without having
    # gone through that (e.g. a stale/pre-existing session), establish it
    # here so a failed attempt has a defined verified=False to fail into,
    # without clobbering a session that already completed verification.
    #
    # Guarded on registry.primary_enabled_for(): a user with NO primary
    # factor must never be stamped pending here. Without this guard, a
    # not-yet-enrolled user GETting this view (reachable by a plain,
    # cross-site top-level navigation) would be marked pending, and
    # MfaMiddleware would then redirect every subsequent request -- including
    # to enroll_factor, the only page that could add a factor -- to a picker
    # with zero options, permanently locking them out.
    if (not session.is_verified(request)
            and registry.primary_enabled_for(request.user)):
        session.start_pending(request)

    if request.method == "POST":
        # A locked-out user gets the same response as a wrong code, so the
        # lockout is not itself an oracle.
        allowed = ratelimit.check(request.user, factor_type)
        verified = False
        if allowed:
            try:
                verified = adapter.complete_verify(
                    request, request.user, request.POST)
            except (ValueError, TypeError, KeyError):
                # Adapter ceremony failures -- clone detection (ValueError),
                # a tampered/malformed credential payload (TypeError from
                # fido2 parsing something that isn't a mapping), or a missing
                # POST field (KeyError/MultiValueDictKeyError, e.g. no
                # `credential`) -- must be indistinguishable from an ordinary
                # wrong code: both in the response returned (falls straight
                # into the same GENERIC_ERROR branch below) and for rate
                # limiting (falls through to record_failure exactly like any
                # other failed attempt). Letting any of these propagate would
                # be an unhandled 500, and the 500-vs-400 split would itself
                # be a weak oracle against that deliberately uniform
                # response.
                verified = False
        if verified:
            ratelimit.clear(request.user, factor_type)
            session.mark_verified(request, factor_type)
            # Trust this browser for MFA_REMEMBER_DAYS so a future login can
            # skip the challenge (see the user_logged_in signal in
            # signals.py, which checks verify_rmb_cookie()). update_rmb_cookie
            # is a no-op unless MFA_REMEMBER_MY_BROWSER is enabled.
            return update_rmb_cookie(request, redirect(next_url))
        if allowed:
            ratelimit.record_failure(request.user, factor_type)
        context["error_message"] = GENERIC_ERROR
        context.update(adapter.begin_verify(request, request.user))
        return render(request, adapter.verify_template, context, status=400)

    context.update(adapter.begin_verify(request, request.user))
    return render(request, adapter.verify_template, context)


# --- Passwordless (passkey) login --------------------------------------------
#
# WebAuthn registration/verification-as-a-second-factor
# (django_mfa/adapters/webauthn.py) assume request.user is already known:
# begin_verify()/complete_verify() scope the credential allow-list to a
# specific, already-authenticated user. Passwordless login is the opposite
# shape -- an anonymous visitor with no username or password, whose identity
# is only discovered *from* the assertion (via the discoverable credential's
# userHandle) -- so it cannot reuse those methods as-is for the begin half.
# It DOES reuse WebAuthnAdapter.complete_verify() for the actual ceremony
# validation and clone detection once the user has been resolved: see
# passkey_complete() below for how the two session-state keys are bridged so
# that reuse is possible without duplicating any of that logic.

BACKEND_PATH = f"{WebAuthnBackend.__module__}.{WebAuthnBackend.__qualname__}"


def passkey_begin(request):
    """Start a passwordless WebAuthn authentication ceremony.

    GET only (it has no side effect beyond stashing a challenge, same as
    verify_factor's GET branch). Passes an *empty* credential list to
    authenticate_begin() -- this is what makes the resulting
    allowCredentials empty in the returned options, which is what tells the
    browser/authenticator "let the user pick any resident (discoverable)
    credential it holds for this RP" instead of restricting the prompt to
    one specific, already-known user's credentials. That emptiness is the
    entire mechanism behind "usernameless" login; see
    test_passkey_begin_produces_an_empty_allow_list in test_passwordless.py.
    """
    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])

    options, state = get_server().authenticate_begin(
        [], user_verification=mfa_settings.MFA_FIDO2_USER_VERIFICATION)
    request.session[PASSKEY_STATE_KEY] = state
    return JsonResponse({"options": json.dumps(dict(options))})


def passkey_complete(request):
    """Finish a passwordless WebAuthn authentication ceremony and log the
    resolved user in.

    POST only. Every failure path -- missing/expired state, a malformed
    payload, a userHandle that resolves to no user, a credential ID the
    resolved user does not hold, a bad signature, or a clone-detected
    (regressed) sign counter -- returns the exact same generic 400 via
    _passkey_failure(). This is deliberate and security-critical: if
    "unknown handle" and "bad signature" produced different responses, an
    attacker could use that difference as an oracle to enumerate which
    opaque handles correspond to real accounts. None of the branches below
    are allowed to leak which specific check failed, in the response body,
    the status code, or which branch raises vs. returns -- they must all
    funnel into the same `return _passkey_failure()`.

    Sign-count/clone-detection enforcement is NOT reimplemented here: once
    the user is resolved, this delegates to
    WebAuthnAdapter.complete_verify(), the exact same method the
    second-factor verification path (verify_factor) uses, so there is only
    ever one copy of that logic to keep correct. The two paths use different
    session keys for their in-flight ceremony state (PASSKEY_STATE_KEY here
    vs. AUTH_STATE_KEY there) since this ceremony starts before any user is
    known and that one starts after -- so the state popped from
    PASSKEY_STATE_KEY is re-stashed under AUTH_STATE_KEY immediately before
    calling complete_verify(), which pops it from there itself. Both keys
    hold the exact same opaque `state` value authenticate_begin()/
    authenticate_complete() round-trip unchanged; only the key name differs.
    """
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    state = request.session.pop(PASSKEY_STATE_KEY, None)
    if state is None:
        return _passkey_failure()

    try:
        raw_credential = json.loads(request.POST["credential"])
        parsed = AuthenticationResponse.from_dict(raw_credential)
    except (KeyError, ValueError, TypeError):
        # KeyError: no `credential` field in the POST body.
        # ValueError: not valid JSON, or valid JSON that from_dict() can't
        #   parse as an AuthenticationResponse (missing/malformed fields).
        # TypeError: from_dict() handed something that isn't a mapping at
        #   all (e.g. a JSON array or scalar).
        return _passkey_failure()

    user_handle = parsed.response.user_handle
    if not user_handle:
        # A real discoverable-credential assertion always carries a
        # userHandle; an authenticator/credential this server never issued a
        # handle to (e.g. a different site's passkey, or a handcrafted
        # payload) does not. Fails the same generic way as every other
        # unresolvable case -- see the docstring above.
        return _passkey_failure()

    try:
        user = user_from_handle(user_handle.decode("utf-8"))
    except UnicodeDecodeError:
        user = None
    if user is None:
        return _passkey_failure()

    # Bridge to WebAuthnAdapter.complete_verify() -- see the docstring above
    # for why the state has to move to AUTH_STATE_KEY rather than
    # complete_verify() being handed PASSKEY_STATE_KEY directly.
    request.session[AUTH_STATE_KEY] = state
    adapter = WebAuthnAdapter()
    try:
        verified = adapter.complete_verify(
            request, user, {"credential": request.POST["credential"]})
    except ValueError:
        # Ceremony rejection (wrong challenge/origin/RP ID, bad signature,
        # credential ID not among this user's own credentials -- which is
        # also how a passkey enrolled to a different user is rejected, see
        # WebAuthnAdapter._existing_credentials()) and clone detection
        # (regressed sign counter) both raise ValueError here. Both fail
        # exactly the same way as an unknown handle.
        request.session.pop(AUTH_STATE_KEY, None)
        return _passkey_failure()

    if not verified:
        # complete_verify() returns False (rather than raising) for its own
        # narrower set of "cannot honour this assertion" cases -- see its
        # docstring in adapters/webauthn.py. Same generic failure either way.
        return _passkey_failure()

    # A passkey assertion only satisfies BOTH factors when it carries the
    # User Verification flag (proof of PIN/biometric, not just possession) --
    # see is_user_verified() below. authenticate_complete() itself only
    # *requires* UV when MFA_FIDO2_USER_VERIFICATION="required"; at the
    # default "preferred" it happily accepts a User-Present-only assertion,
    # so that has to be checked independently here, the same way the
    # adapter independently re-parses the sign counter (fido2 2.2.1's
    # authenticate_complete() return value carries neither). Mark the
    # session verified BEFORE calling auth.login(): the user_logged_in
    # receiver in signals.py (stamp_pending_verification) checks
    # session.is_verified(request) and skips re-stamping the session pending
    # when it's already True -- doing this first is what makes a
    # UV-carrying passkey login satisfy both factors in one step. For a
    # UP-only assertion, mark_verified() is deliberately NOT called: the
    # user is still logged in (WebAuthn login succeeded), but that same
    # signal receiver then stamps the session pending exactly as it would
    # for a plain password login, since is_verified() is still False at
    # that point -- the user must still complete a second-factor challenge.
    if parsed.response.authenticator_data.is_user_verified():
        session.mark_verified(request, "webauthn")

    auth.login(request, user, backend=BACKEND_PATH)
    return redirect(_safe_next(request))


# --- Remember-my-browser cookie helpers -------------------------------------
#
# Carried over from the legacy views.py unchanged apart from reading
# Authenticator (type=totp, data["secret"]) instead of UserOTP.secret_key.
# The secret may be encrypted at rest (see django_mfa.crypto), so it is run
# through decrypt() before being used to derive the cookie salt.

MFA_COOKIE_PREFIX = "RMB_"


def _generate_cookie_salt(user):
    auth = Authenticator.objects.filter(
        user=user, type=Authenticator.Type.TOTP).first()
    if auth is None:
        return ''
    secret = decrypt(auth.data.get("secret", ""))
    # out of paranoia only use half the secret to generate the salt
    uselen = int(len(secret) / 2)
    half_secret = secret[:uselen]
    m = hashlib.sha256()
    m.update(half_secret.encode("utf-8"))
    cookie_salt = m.hexdigest()
    return cookie_salt


# update Remember-My-Browser cookie
def update_rmb_cookie(request, response):
    remember_my_browser = mfa_settings.MFA_REMEMBER_MY_BROWSER
    remember_days = mfa_settings.MFA_REMEMBER_DAYS
    if remember_my_browser:
        # better not to reveal the username.  Revealing the number seems harmless
        cookie_name = MFA_COOKIE_PREFIX + str(request.user.pk)
        cookie_salt = _generate_cookie_salt(request.user)
        response.set_signed_cookie(cookie_name, True, salt=cookie_salt, max_age=remember_days * 24 * 3600,
                                   secure=(not settings.DEBUG), httponly=True)
    return response


# verify Remember-My-Browser cookie
# returns True if browser is trusted and no code verification needed
def verify_rmb_cookie(request):
    remember_my_browser = mfa_settings.MFA_REMEMBER_MY_BROWSER
    max_cookie_age = mfa_settings.MFA_REMEMBER_DAYS * 24 * 3600
    if not remember_my_browser:
        return False

    cookie_name = MFA_COOKIE_PREFIX + str(request.user.pk)
    cookie_salt = _generate_cookie_salt(request.user)
    if not cookie_salt:
        return False
    cookie_value = request.get_signed_cookie(
        cookie_name, False, max_age=max_cookie_age, salt=cookie_salt)
    # if the cookie value is True and the signature is good than the browser can be trusted
    return cookie_value


def delete_rmb_cookie(request, response):
    cookie_name = MFA_COOKIE_PREFIX + str(request.user.pk)
    response.delete_cookie(cookie_name)
    return response
