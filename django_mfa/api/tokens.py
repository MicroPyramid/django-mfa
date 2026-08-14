"""MFA state for a client that cannot hold a cookie.

``MFA_API_AUTHENTICATION`` answers *who you are* from a bearer token, but
whether this caller has passed a challenge -- and how recently -- is read from
``request.session`` by the same code the browser flow uses. A client that
discards cookies therefore arrives with a brand-new empty session on every
request, and a verification completed in one can never be seen by the next.

This module closes that without inventing a second home for MFA state. The
token a client holds **is** a session key: ``issue()`` mints a server-side
session, hands back its key, and ``load()`` puts it on the request as
``request.session`` when the client presents it in the ``X-MFA-Session``
header. Everything downstream -- django_mfa.session, the enforcement rungs,
step-up freshness -- runs unchanged and unaware.

What that buys, and why it beat a signed stateless token holding
``{"verified": true}``:

* **Revocation.** ``DELETE`` on the session endpoint flushes the row. A signed
  token is valid until it expires, and cannot be withdrawn from a device its
  holder has lost.
* **Expiry, already solved.** ``SESSION_COOKIE_AGE`` and ``clearsessions``
  apply as-is.
* **One reader.** ``django_mfa/session.py`` stays the only module that touches
  the ``mfa`` session key, which is the rule the rest of this package is
  built on.

Three properties below are load-bearing rather than tidy; each says so at its
own definition: the token is bound to the user it was issued to, no
``Set-Cookie`` is ever sent for one, and CSRF is enforced for cookie requests
only.

Not covered: the passkey endpoints. Passwordless login establishes identity,
and a token cannot be issued before there is an identity to bind it to --
minting an unbound one and rotating it after the ceremony would be textbook
session fixation for the window in between. Those two endpoints stay
cookie-borne; see docs/rest_api.md.
"""

from importlib import import_module

from django.conf import settings as django_settings

#: The request header a client presents its token in. Deliberately not
#: ``Authorization``: that is where the client's *own* credential already
#: lives (a DRF token, a JWT), and this is a second, orthogonal one -- an
#: answer to "has this caller passed MFA", not "who is this caller".
HEADER = "X-MFA-Session"
META_KEY = "HTTP_X_MFA_SESSION"

#: Where issue() records the user a token belongs to, inside the session it
#: mints. See load() for why a token that lacks this is refused rather than
#: trusted.
USER_KEY = "_mfa_api_user"


class TokenSessionsUnsupported(Exception):
    """``SESSION_ENGINE`` cannot mint a server-side session key.

    True of ``django.contrib.sessions.backends.signed_cookies``, where the
    "key" is the signed payload itself: it changes every time the session data
    changes, so a token issued before a challenge would no longer name the
    session that passed it. There is nothing to hand out, and pretending
    otherwise would give a client a token that silently stopped working at the
    exact moment it started to matter.
    """


def _store(session_key=None):
    return import_module(django_settings.SESSION_ENGINE).SessionStore(
        session_key)


def token_from(request):
    """The token this request presented, or None.

    Cheap and non-validating on purpose -- it answers "is this a token-borne
    request", which is the question the CSRF branch in api/views.py asks
    before it has a user to validate against.
    """
    return request.META.get(META_KEY) or None


def issue(user):
    """Mint a session for ``user`` and return ``(token, expires_in)``."""
    store = _store()
    # str(): the default session serializer is JSON, and a UUID primary key
    # (or any other non-JSON-native pk a swapped AUTH_USER_MODEL might use)
    # would otherwise raise on save. load() compares the same way.
    store[USER_KEY] = str(user.pk)
    store.create()
    if store.session_key is None:
        raise TokenSessionsUnsupported(django_settings.SESSION_ENGINE)
    return store.session_key, store.get_expiry_age()


def load(request, user):
    """The session this request's token names, or None to refuse it.

    Returns None both for "no token presented" and for a token that exists but
    does not belong to ``user``. The caller distinguishes them by whether
    ``token_from()`` was truthy.

    **The binding check is the security of this module.** Without it, a client
    could present a token issued to somebody else alongside its own identity
    credential and inherit that session's verified state -- a complete
    second-factor bypass needing only a token overheard once. It is also what
    keeps an ordinary browser ``sessionid`` from being replayed through this
    header: no browser session carries USER_KEY, so none is accepted here, and
    the CSRF exemption that rides on the header therefore cannot be reached
    with a stolen cookie.
    """
    key = token_from(request)
    if key is None:
        return None
    store = _store(key)
    # Reading a nonexistent key yields an empty session rather than raising,
    # so an expired, revoked or invented token simply carries no USER_KEY and
    # fails the comparison below alongside a genuinely mismatched one.
    if store.get(USER_KEY) != str(user.pk):
        return None
    return store


def persist(request):
    """Save a token-borne session without ever setting a cookie.

    SessionMiddleware writes ``Set-Cookie`` on the way out for any session it
    finds modified. For a token client that cookie is at best ignored and at
    worst confusing -- a browser holding both would send a session cookie the
    server never meant it to have. Saving here and clearing ``modified``
    leaves the middleware nothing to do, which is the whole trick.
    """
    if request.session.modified:
        request.session.save()
        request.session.modified = False


def revoke(request):
    """Destroy the token-borne session this request presented, if any.

    Guarded on a token actually being in play: an unguarded flush() would log
    a *cookie* client out of Django entirely, which is not what "revoke my API
    token" can be allowed to mean.
    """
    if token_from(request) is None:
        return False
    request.session.flush()
    return True
