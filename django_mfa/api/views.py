"""JSON endpoints, one per thing the HTML views do.

Every response body is a JSON object. Failures are always::

    {"error": {"code": "<stable machine-readable slug>", "detail": "..."}}

``code`` is the part to branch on; ``detail`` is translated prose that may
be reworded in any release.

Two properties are inherited from the HTML views and must survive any change
here, because losing either is silent:

* **Every verification failure looks the same.** A wrong code, a malformed
  payload, a replayed ceremony, a clone-detected authenticator and a
  rate-limited attempt all return the identical 400 body. Distinguishing
  them would hand an attacker an oracle -- and the rate-limit case
  especially, since a distinguishable lockout tells them exactly when to
  back off.
* **The enroll endpoints are not reachable while a session is pending.**
  Enrolling marks a session verified, so a pending user allowed to enroll
  could satisfy their own challenge with a factor of their choosing instead
  of the one they hold -- a complete second-factor bypass for anyone who has
  the password.

  MfaMiddleware does **not** back this up. It lets every request into this
  namespace through, because the only thing it could do is redirect, and a
  302 to an HTML page is not an answer a JSON client can act on (see
  MfaMiddleware.is_api_request). The ``endpoint()`` decorator below is
  therefore the *only* gate on these URLs, and an endpoint added without it
  is not a smaller bug than it would be elsewhere -- it is a bigger one.
  test_api.py's EveryEndpointIsGatedTests walks this module's URLconf and
  asserts the refusal for every route outside a small explicit allowlist,
  so a new one cannot arrive ungated unnoticed.
"""

import json
from functools import wraps

from django.contrib import auth as django_auth
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils.translation import gettext_lazy as _
from django.views.decorators.csrf import csrf_protect

from django_mfa import decorators, events, flows, session
from django_mfa.adapters.recovery_codes import RecoveryCodesAdapter
from django_mfa.api import auth, tokens
from django_mfa.conf import settings as mfa_settings
from django_mfa.models import Authenticator
from django_mfa.registry import registry
from django_mfa.views import verify as verify_views
from django_mfa.views.verify import GENERIC_ERROR

#: Reused verbatim from the HTML passkey endpoint rather than reworded, so
#: the two cannot come to describe the same failure differently.
PASSKEY_ERROR = _("Passkey sign-in failed.")

#: How each enforcement rung renders as JSON. The rungs themselves come from
#: django_mfa.decorators, so this table is a *rendering*, never a second
#: policy -- add a rung there and this fails loudly with a KeyError rather
#: than quietly letting the request through.
GATES = {
    decorators.UNAUTHENTICATED: (
        401, "unauthenticated", _("Authentication is required.")),
    decorators.PENDING: (
        403, "verification_required",
        _("This session must complete a second-factor challenge first.")),
    decorators.UNENROLLED: (
        403, "enrollment_required",
        _("This account must enroll a second factor first.")),
    decorators.STALE: (
        403, "stepup_required",
        _("This action needs a recent second-factor challenge.")),
}


def error(status, code, detail):
    """The one failure shape.

    Built fresh per call rather than reused from a module-level constant: a
    response object is mutated as it is rendered, so sharing one across
    requests is a bug that only shows under concurrency.
    """
    return JsonResponse({"error": {"code": code, "detail": detail}},
                        status=status)


def _gate(state):
    return error(*GATES[state])


def json_body(request):
    """The request body as a dict.

    An absent body is ``{}`` rather than an error: several endpoints take no
    input, and requiring `{}` from them would be pedantry. A body that is
    valid JSON but not an object is rejected, because every adapter indexes
    what it is handed.
    """
    if not request.body:
        return {}
    data = json.loads(request.body.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("body must be a JSON object")
    return data


def endpoint(*methods, anonymous=False, require_verified=True,
             allow_unenrolled=True, stepup=False):
    """Wrap a view with the method check, authentication and gating.

    ``require_verified=False`` is what lets the *verify* endpoints work while
    a session is pending -- they are how it stops being pending. Everything
    else keeps the default, and in particular the enroll endpoints must
    never be given it (see this module's docstring).

    ``stepup=True`` adds the freshness rung, matching
    ``@mfa_recent_required`` on the corresponding HTML view.

    Also the one place a token-borne session is swapped onto the request (see
    django_mfa/api/tokens.py) and the one place CSRF is decided. Both happen
    around the gates rather than inside a view, because every endpoint needs
    them and an endpoint that quietly skipped either would be the bug this
    module's docstring is about.
    """
    def decorator(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            if request.method not in methods:
                return error(405, "method_not_allowed",
                             _("This endpoint does not accept %(method)s.")
                             % {"method": request.method})
            if anonymous:
                return view(request, *args, **kwargs)

            user = auth.resolve_user(request)
            if user is None:
                return _gate(decorators.UNAUTHENTICATED)
            # Assigned before anything downstream runs: the adapters create
            # and query Authenticator rows against request.user directly, so
            # a custom MFA_API_AUTHENTICATION resolver would otherwise enroll
            # onto whichever account the session happened to name.
            request.user = user

            # Swap in the token-borne session, if one was presented, BEFORE
            # any gate reads it -- every rung below asks django_mfa.session
            # about request.session, and the point of a token is that it names
            # a different one from the (absent, or irrelevant) cookie's.
            token_session = tokens.load(request, user)
            if token_session is not None:
                request.session = token_session
            elif tokens.token_from(request) is not None:
                # Presented something, and it was expired, revoked, invented,
                # or issued to a different account. Falling back to the cookie
                # session would silently ignore what the client asked for;
                # answer the question it actually asked instead.
                return error(401, "invalid_mfa_session",
                             _("This MFA session token is not valid."))

            state = decorators.enforcement_state(
                request, require_primary_factor=not allow_unenrolled)
            if state == decorators.PENDING and not require_verified:
                state = None
            if state is None and stepup:
                state = decorators.recent_enforcement_state(request)
            if state is not None:
                return _gate(state)

            try:
                response = view(request, *args, **kwargs)
            except ValueError as exc:
                # json_body() and nothing else: an adapter's own ValueError
                # is caught inside flows, never here.
                response = error(400, "malformed_body", str(exc))
            # Both branches, so that a rejected attempt still persists what the
            # attempt changed -- adapters/email.py counts guesses against an
            # issued code in the session, and dropping that write would make
            # its MAX_ATTEMPTS cap unenforceable for token clients. Deliberately
            # NOT in a finally: an unhandled exception must leave the session
            # exactly as it was.
            if token_session is not None:
                tokens.persist(request)
            return response

        # CSRF applies to every non-safe method, which is nearly all of
        # these. A session-authenticated JSON endpoint is exactly as
        # forgeable as a form post without it.
        protected = csrf_protect(wrapped)

        @wraps(view)
        def dispatch(request, *args, **kwargs):
            # CSRF defends against a request the *browser* sends credentials
            # with on its own. Cookies are attached automatically; headers are
            # not, and cannot be set cross-origin without a preflight the
            # target site has to allow. A request carrying no cookie at all
            # therefore has no ambient credential to forge, which is the same
            # split DRF draws between SessionAuthentication (enforced) and
            # TokenAuthentication (exempt).
            #
            # The test is "no cookies", not "presented a token", and that is
            # deliberate twice over. A cookie-less client has no token yet
            # when it calls POST session/ to mint its first one, so keying on
            # the token would make the endpoint unreachable by exactly the
            # clients it exists for. And keying on *any* cookie being absent,
            # rather than on the session cookie specifically, keeps this safe
            # for a host whose MFA_API_AUTHENTICATION resolver reads a cookie
            # of its own -- that credential is ambient too, and it still gets
            # CSRF.
            if not request.COOKIES:
                return wrapped(request, *args, **kwargs)
            return protected(request, *args, **kwargs)

        # The *global* CsrfViewMiddleware would otherwise reject the token
        # request before this view ran and the branch above never happen, so
        # the resolved view is marked exempt and csrf_protect re-imposes the
        # check inline for every cookie-borne request. Marking the outermost
        # callable is what matters: that is the one the middleware inspects.
        dispatch.csrf_exempt = True
        return dispatch

    return decorator


def _adapter_or_404(factor_type):
    try:
        return registry.get(factor_type)
    except KeyError:
        raise Http404(f"Unknown factor {factor_type!r}") from None


def serialize_authenticator(authenticator):
    """One enrolled factor, as JSON.

    ``Authenticator.data`` is absent and must stay absent: it holds the TOTP
    shared secret, the recovery-code hashes and the WebAuthn credential.
    This is the same rule AuthenticatorAdmin follows, for the same reason --
    see its docstring.
    """
    return {
        "id": authenticator.pk,
        "type": authenticator.type,
        "name": authenticator.name,
        "verbose_name": authenticator.get_type_display(),
        "created_at": authenticator.created_at,
        "last_used_at": authenticator.last_used_at,
    }


def serialize_adapter(adapter):
    return {"type": adapter.type, "verbose_name": adapter.verbose_name,
            "supports_multiple": adapter.supports_multiple}


@endpoint("GET", require_verified=False)
def state(request):
    """Everything a client needs to render the right screen.

    Deliberately reachable while pending: a client that could not ask "what
    can I verify with?" until after verifying would have nothing to draw the
    challenge screen from.
    """
    return JsonResponse({
        "verified": session.is_verified(request),
        "pending": session.is_pending(request),
        "verified_at": session.verified_at(request),
        "authenticators": [
            serialize_authenticator(a) for a in Authenticator.objects.filter(
                user=request.user).order_by("type", "created_at")],
        # What this user can verify with right now (includes recovery codes)
        # versus what they could still add. The two answer different
        # questions and a client needs both -- see Registry.enabled_for.
        "can_verify_with": [serialize_adapter(a)
                            for a in registry.enabled_for(request.user)],
        "can_enroll": [serialize_adapter(a)
                       for a in registry.available_for(request.user)],
        "has_primary_factor": registry.has_primary_factor(request.user),
        "recovery_codes_remaining":
            RecoveryCodesAdapter().remaining(request.user),
        "stepup_max_age": mfa_settings.MFA_STEPUP_MAX_AGE,
    })


@endpoint("POST", "DELETE", require_verified=False)
def mfa_session(request):
    """Mint or revoke an MFA session token, for a client without cookies.

    Reachable while pending, and it has to be: a token is how a client gets
    far enough to *be* challenged, and the one it mints is empty --
    unverified, holding nothing but the identity it is bound to. Granting one
    confers no access that the caller's own credential did not already carry.

    ``DELETE`` revokes the token presented on that request, and only that one:
    a caller with no token gets ``revoked: false`` rather than having its
    cookie session flushed out from under it (see tokens.revoke).
    """
    if request.method == "DELETE":
        return JsonResponse({"revoked": tokens.revoke(request)})
    try:
        token, expires_in = tokens.issue(request.user)
    except tokens.TokenSessionsUnsupported:
        # 501, not 400: the client's request was perfectly well formed and
        # there is nothing it can change to make this work. The server is
        # configured with a session engine that has no server-side key to
        # hand out.
        return error(
            501, "token_sessions_unsupported",
            _("This server stores sessions in a way that cannot issue a "
              "token. Use cookie-based session authentication instead."))
    return JsonResponse({"token": token, "expires_in": expires_in,
                         "header": tokens.HEADER})


@endpoint("POST", stepup=True)
def enroll_begin(request, factor_type):
    """Start enrolling a factor.

    POST rather than GET despite reading like a fetch: beginning has real
    side effects -- the email factor *sends mail*, WebAuthn stashes ceremony
    state in the session -- and POST is also what brings CSRF protection.
    The HTML views use GET here only because rendering a page has to.

    The body is whatever the adapter returned, passed through unchanged. For
    WebAuthn that means ``options`` is a JSON-encoded *string* to be parsed,
    not a nested object: it is the identical blob the bundled JavaScript
    parses, and re-encoding it here would create a second shape of the same
    thing for somebody to keep in sync.
    """
    adapter = _adapter_or_404(factor_type)
    if not adapter.supports_enroll:
        raise Http404(f"Factor {factor_type!r} is not enrolled this way")
    return JsonResponse(adapter.begin_enroll(request))


@endpoint("POST", stepup=True)
def enroll_complete(request, factor_type):
    adapter = _adapter_or_404(factor_type)
    if not adapter.supports_enroll:
        raise Http404(f"Factor {factor_type!r} is not enrolled this way")
    try:
        authenticator = flows.attempt_enroll(
            request, factor_type, json_body(request))
    except flows.FactorRejected:
        return error(400, "invalid", GENERIC_ERROR)
    return JsonResponse({
        "authenticator": serialize_authenticator(authenticator),
        # The HTML flow redirects a user with no codes to generate some.
        # An API client has no redirect to follow, so it is told instead.
        "recovery_codes_pending": not Authenticator.objects.filter(
            user=request.user,
            type=Authenticator.Type.RECOVERY_CODES).exists(),
    }, status=201)


@endpoint("POST", require_verified=False)
def verify_begin(request, factor_type):
    """Issue a challenge. Reachable while pending, by definition."""
    adapter = _adapter_or_404(factor_type)
    if (not session.is_verified(request)
            and registry.primary_enabled_for(request.user)):
        # Same defensive stamp verify_factor makes, and guarded the same
        # way: a user with no primary factor must never be marked pending,
        # or nothing can ever un-pend them.
        session.start_pending(request)
    return JsonResponse(adapter.begin_verify(request, request.user))


@endpoint("POST", require_verified=False)
def verify_complete(request, factor_type):
    """Answer a challenge.

    Both outcomes are as uniform as the HTML view's: one 200 shape, one 400
    shape, with nothing in either saying which check failed or whether the
    attempt was even evaluated.
    """
    _adapter_or_404(factor_type)
    if (not session.is_verified(request)
            and registry.primary_enabled_for(request.user)):
        session.start_pending(request)
    if not flows.attempt_verify(request, request.user, factor_type,
                                json_body(request)):
        return error(400, "invalid", GENERIC_ERROR)
    return JsonResponse({"verified": True,
                         "verified_at": session.verified_at(request)})


@endpoint("POST", stepup=True)
def recovery_codes(request):
    """Generate recovery codes, once.

    ``codes`` is null when a set already exists. The plaintext is returned
    by generate() exactly once and is never stored, so there is nothing to
    return on a second call -- see views.manage.recovery_codes.
    """
    adapter = RecoveryCodesAdapter()
    if adapter.is_enabled(request.user):
        return JsonResponse({"codes": None,
                             "remaining": adapter.remaining(request.user)})

    codes = adapter.generate(request.user)
    events.factor_added.send_robust(
        sender=RecoveryCodesAdapter, user=request.user,
        authenticator=Authenticator.objects.get(
            user=request.user, type=Authenticator.Type.RECOVERY_CODES),
        request=request)
    return JsonResponse({"codes": codes, "remaining": len(codes)}, status=201)


@endpoint("DELETE", stepup=True)
def remove_factor(request, pk):
    try:
        authenticator = get_object_or_404(
            Authenticator, pk=int(pk), user=request.user)
    except (TypeError, ValueError, OverflowError):
        # A pk that does not parse, or parses too large for the column, must
        # be the same 404 a someone-else's pk gets rather than a 500.
        raise Http404("No such authenticator") from None

    if (authenticator.type == Authenticator.Type.WEBAUTHN
            and mfa_settings.MFA_OWNED_BY_ENTERPRISE):
        return error(403, "managed_by_enterprise",
                     _("This security key is managed by your organization "
                       "and cannot be removed here."))

    flows.remove_factor(request, authenticator)
    return JsonResponse({"removed": True})


# --- Passwordless (passkey) login -------------------------------------------
#
# The HTML pair already speaks JSON on the way in (mfa:passkey_begin returns
# options as JSON), but mfa:passkey_complete answers success with a 302 to
# LOGIN_REDIRECT_URL, which is exactly wrong for a client that wanted to know
# whether it is now logged in. These return that answer as data instead.
#
# The existing endpoints keep their current shapes unchanged, including
# _passkey_failure()'s flat {"error": "..."} body, which is deliberately NOT
# migrated to this module's envelope: it is a response hosts already parse.


@endpoint("GET", anonymous=True)
def passkey_begin(request):
    """Start a passwordless ceremony. Identical to the HTML endpoint."""
    return verify_views.passkey_begin(request)


@endpoint("POST", anonymous=True)
def passkey_complete(request):
    """Finish a passwordless ceremony and log the resolved user in.

    Every failure returns one identical 400 -- see
    resolve_passkey_assertion(), which is where that uniformity is enforced
    and why it matters.

    ``verified`` distinguishes the two kinds of success that look alike from
    here: a User-Verified assertion (a PIN or biometric) satisfies both
    factors at once, while a User-Present-only one logs the user in with a
    session still pending a second factor. A client that treats them alike
    will drop people at a screen they cannot leave.
    """
    try:
        credential = json_body(request).get("credential")
    except ValueError:
        return error(400, "invalid", PASSKEY_ERROR)
    if credential is None:
        return error(400, "invalid", PASSKEY_ERROR)

    user = verify_views.resolve_passkey_assertion(request, credential)
    if user is None:
        return error(400, "invalid", PASSKEY_ERROR)

    django_auth.login(request, user, backend=verify_views.BACKEND_PATH)
    return JsonResponse({
        "authenticated": True,
        "verified": session.is_verified(request),
        "verified_at": session.verified_at(request),
    })
