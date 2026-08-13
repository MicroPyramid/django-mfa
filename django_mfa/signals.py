from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver

from django_mfa import session
from django_mfa.conf import settings as mfa_settings

# Re-exported so `from django_mfa.signals import factor_added` works -- the
# import path a Django developer tries first. The definitions live in
# django_mfa/events.py; see that module's docstring for why.
from django_mfa.events import (  # noqa: F401
    factor_added,
    factor_removed,
    mfa_verification_failed,
    mfa_verified,
    recovery_code_used,
)
from django_mfa.registry import registry
from django_mfa.views import verify_rmb_cookie

# A module-level import was tried and works cleanly: django_mfa.views (via
# django_mfa.views.verify) imports django_mfa.registry, which imports
# django_mfa.models -- neither of those import django_mfa.signals or
# django_mfa.apps back, so there is no cycle. apps.ready() already imports
# django_mfa.adapters (which also pulls in the registry) before importing
# this module, so by the time this file is imported the registry is fully
# populated too.


@receiver(user_logged_in)
def stamp_pending_verification(sender, request, user, **kwargs):
    """Mark the session as awaiting a second factor.

    Replaces the old contract where host projects had to set
    ``u2f_pre_verify_user_pk`` and ``u2f_pre_verify_user_backend`` by hand.
    Skipped when the session is already verified — a passkey login (Task 18)
    satisfies both factors at once.

    A trusted browser (see ``MFA_REMEMBER_MY_BROWSER`` /
    ``django_mfa.views.verify_rmb_cookie``) short-circuits the challenge: if
    the signed cookie proves this browser already passed a second factor
    within ``MFA_REMEMBER_DAYS``, the session is marked verified immediately
    instead of pending. ``verify_rmb_cookie`` itself returns ``False``
    whenever ``MFA_REMEMBER_MY_BROWSER`` is off, so this is a no-op and every
    login is challenged normally unless a host project opts in.
    """
    if session.is_verified(request):
        return
    if registry.primary_enabled_for(user):
        # registry.primary_enabled_for() (not models.Authenticator's manager)
        # is the single source of truth for "is this user protected" -- see
        # Adapter.counts_as_primary_factor / Registry.primary_enabled_for()
        # in registry.py. Using anything else here (e.g. a hardcoded set of
        # type strings) can silently diverge from it: a third-party adapter
        # that opts in via counts_as_primary_factor would be enrollable and
        # shown as enabled without ever being challenged, and
        # registry.unregister("webauthn") -- the opt-out checks.py itself
        # recommends -- would leave already-enrolled users facing a
        # zero-option picker instead of simply not being challenged for a
        # factor type that's no longer offered.
        #
        # verify_rmb_cookie() reads request.user. django.contrib.auth.login()
        # only back-fills that attribute when the request already had one
        # (true for a real request, which passed through
        # AuthenticationMiddleware first) -- Client.login(), used pervasively
        # in this test suite, fires this signal via a bare HttpRequest that
        # never had .user set at all. Set it explicitly rather than relying
        # on login()'s conditional assignment; we already have the user this
        # signal is about.
        request.user = user
        if verify_rmb_cookie(request):
            session.mark_verified(request, "remember_my_browser")
        else:
            session.start_pending(request)


@receiver(user_logged_in)
def set_quicklogin_hint(sender, request, user, **kwargs):
    """Stash the logging-in user on the request for MfaMiddleware to turn
    into a signed MFA_QUICKLOGIN hint cookie once a response exists.

    This can't set the cookie directly: a signal receiver fires deep inside
    auth.login(), with no HttpResponse in hand yet, and django_mfa does not
    own the login view whose response that eventually becomes -- the
    password login page belongs to the host project, and this signal is the
    only hook common to every login regardless of which view (or, for
    passkey logins, django_mfa.views.verify.passkey_complete itself) called
    auth.login(). Stashing the user on `request` and letting MfaMiddleware.
    process_response() apply it once the view has returned a real response
    is the only place in the request lifecycle where both pieces (who
    logged in, and a response to attach a cookie to) are available together.

    (django.test.Client.login(), used throughout this suite, deliberately
    reproduces the "no response" half of this problem: it fabricates a bare
    HttpRequest and never produces an HttpResponse at all -- see
    django.test.client.Client._login(). Tests that need to observe this
    cookie use RequestFactory + MfaMiddleware directly instead, mirroring
    the pattern test_enforcement.py already uses for the RMB cookie.)
    """
    if mfa_settings.MFA_QUICKLOGIN:
        request._mfa_quicklogin_login = user


@receiver(user_logged_out)
def clear_quicklogin_hint(sender, request, **kwargs):
    """Mirror of set_quicklogin_hint() for logout: flag the request so
    MfaMiddleware.process_response() deletes the hint cookie. Unconditional
    (not gated on MFA_QUICKLOGIN) so a cookie set while the feature was on
    still gets cleaned up if it's since been turned off.
    """
    request._mfa_quicklogin_logout = True
