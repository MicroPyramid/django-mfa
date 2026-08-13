# django_mfa/quicklogin.py
#
# MFA_QUICKLOGIN: an opt-in, signed-nothing hint cookie identifying which
# account this browser last logged into, so a host project's login page can
# greet a returning user with a passkey prompt instead of a bare
# username/password form. It is a UX hint only, never a credential -- it
# does not, by itself, authenticate or log anyone in. Resolving the cookie
# back to a user (user_from_hint) only tells the login page *whose* passkey
# prompt to show; the user must still complete a real WebAuthn ceremony
# (django_mfa.views.verify.passkey_begin/passkey_complete) to actually sign
# in.
#
# Reuses the handles.py idiom (an opaque, stored per-user handle) rather
# than inventing a second signed-cookie scheme: the same "must survive
# SECRET_KEY rotation and never leak identity" reasoning documented in
# handles.py applies here too, since this cookie is set with a 1-year
# max-age and would otherwise go stale on every key rotation exactly like an
# unstored WebAuthn user handle would.
from django_mfa.conf import settings as mfa_settings
from django_mfa.handles import user_from_handle, user_handle_for

COOKIE_NAME = "mfa_quicklogin"
MAX_AGE = 60 * 60 * 24 * 365


def set_hint(response, user, secure):
    """Attach the quicklogin hint cookie for ``user`` to ``response``.

    A no-op (returns ``response`` unchanged) whenever MFA_QUICKLOGIN is off
    -- the default -- so nothing about this feature is observable unless a
    host project opts in.
    """
    if not mfa_settings.MFA_QUICKLOGIN:
        return response
    response.set_cookie(COOKIE_NAME, user_handle_for(user), max_age=MAX_AGE,
                        httponly=True, samesite="Lax", secure=secure)
    return response


def clear_hint(response):
    """Remove the quicklogin hint cookie from ``response`` (e.g. on logout).

    Unconditional -- unlike set_hint(), this runs even if MFA_QUICKLOGIN has
    since been turned off, so a stale cookie set while the feature was on
    doesn't outlive the session that created it.
    """
    response.delete_cookie(COOKIE_NAME, samesite="Lax")
    return response


def user_from_hint(value):
    """Resolve a quicklogin cookie value back to a user, or None.

    Never raises: ``value`` is untrusted client-supplied input (a missing,
    tampered, or stale cookie), and user_from_handle() already returns None
    rather than raising for anything malformed.
    """
    return user_from_handle(value) if value else None
