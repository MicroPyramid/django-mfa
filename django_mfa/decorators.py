"""Per-view MFA enforcement.

MFA_REQUIRED (django_mfa.policy) decides which *users* must hold a factor.
These decide which *views* require one, for everybody, which a user predicate
cannot express: "MFA on the billing flow" is a property of the view.

Share two destinations with MfaMiddleware, in the same order: pending ->
the verify picker, no primary factor -> the security page. The second
rung differs in what triggers it, though: the middleware fires it only
for a user MFA_REQUIRED applies to, while these fire it for anyone who
reaches a decorated view -- that is the whole point of having both.
Add a rung the middleware doesn't have: unauthenticated -> LOGIN_URL. MfaMiddleware
passes an unauthenticated request straight through (it isn't a login
gate); a view behind only this decorator may have no other login gate in
front of it, so the decorator supplies that rung itself.
"""

from functools import wraps

from django.contrib.auth.views import redirect_to_login
from django.shortcuts import resolve_url
from django.urls import reverse

from django_mfa import session
from django_mfa.conf import settings as mfa_settings


def _enforce(request, require_primary_factor=True):
    """Return a redirect response, or None to let the request through.

    ``require_primary_factor`` gates only the third rung below. It exists
    for mfa_recent_required/MfaRecentRequiredMixin, which reuse this
    function for the authenticated/pending rungs. By default those callers
    pass it True too, so a factorless user is redirected here exactly as
    mfa_required does. Their own allow_unenrolled=True escape hatch (for the
    built-in enrollment views only) passes False instead, deferring to
    _enforce_recent()'s own, more permissive handling of a factorless user
    (let them through, since there is nothing for them to re-verify) --
    which would otherwise never be reached, since this rung would redirect
    first. mfa_required/MfaRequiredMixin never pass this, so their
    behaviour is unchanged.
    """
    from django_mfa.registry import registry

    user = request.user
    if not user.is_authenticated:
        return redirect_to_login(request.get_full_path())
    if session.is_pending(request):
        return redirect_to_login(request.get_full_path(),
                                 resolve_url(reverse("mfa:verify")), "next")
    if require_primary_factor and not registry.has_primary_factor(user):
        # has_primary_factor(), not enabled_for(): a user holding only
        # recovery codes is not protected, and recovery codes must never be
        # somebody's sole second factor. has_primary_factor(), not
        # primary_enabled_for(): only the yes/no answer is needed here, and
        # this runs on every request to a decorated view.
        return redirect_to_login(
            request.get_full_path(),
            resolve_url(reverse("mfa:security_settings")), "next")
    return None


def mfa_required(view_func):
    """Require a verified second factor for this view."""
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        response = _enforce(request)
        if response is not None:
            return response
        return view_func(request, *args, **kwargs)

    return _wrapped


class MfaRequiredMixin:
    """Class-based-view form of ``mfa_required``.

    Mix in FIRST, so dispatch() runs before the view's own.
    """

    def dispatch(self, request, *args, **kwargs):
        response = _enforce(request)
        if response is not None:
            return response
        return super().dispatch(request, *args, **kwargs)


#: Methods that are safe to replay after a detour through the verify flow.
#: An unsafe request's body cannot survive the redirect, so those are sent
#: to a landing page instead -- see _enforce_recent.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def _enforce_recent(request, max_age, next_url):
    """The step-up rung: a recent challenge, not merely a verified session.

    Returns a redirect response, or None to let the request through. Runs
    only AFTER _enforce() has passed, so request.user is authenticated and
    the session is verified by the time this is reached.
    """
    from django_mfa.registry import registry

    resolved = (max_age if max_age is not None
                else mfa_settings.MFA_STEPUP_MAX_AGE)
    if resolved is None:
        return None
    if not registry.has_primary_factor(request.user):
        # Only reachable at all when the caller passed allow_unenrolled=True
        # (_enforce() already redirected a factorless user away otherwise).
        # Nothing to re-verify, and this is the first-enrollment path.
        # Gating it would wall a factorless user out of the only pages that
        # could give them a factor -- the same lockout
        # signals.stamp_pending_verification guards against by refusing to
        # stamp such a user pending.
        return None
    if session.is_fresh(request, resolved):
        return None
    if request.method in SAFE_METHODS:
        target = request.get_full_path()
    else:
        # A POST body does not survive a redirect, and manage_factors is
        # POST-only (405 on GET), so replaying its URL after verification
        # would land the user on that 405. Send them to a page they can act
        # from instead; they re-click.
        target = next_url or reverse("mfa:security_settings")
    return redirect_to_login(target, resolve_url(reverse("mfa:verify")), "next")


def mfa_recent_required(max_age=None, next_url=None, allow_unenrolled=False):
    """Require a *recent* second-factor challenge, not just a verified session.

    By default (``allow_unenrolled=False``) this is strictly stronger than
    ``mfa_required``: it applies every rung ``mfa_required`` does --
    including redirecting a factorless user to ``mfa:security_settings`` --
    and then, for a user who passes that, the freshness rung on top. This is
    what a host project's own sensitive views (e.g. ``transfer_funds`` in
    docs/enforcement.md) get.

    ``allow_unenrolled=True`` switches off the factorless-user redirect and
    lets such a user through instead, since they have nothing to re-verify.
    This is for the built-in enrollment views only (``enroll_factor``,
    ``recovery_codes``) -- gating the very pages that let a user acquire a
    factor would lock them out permanently. Most callers should not pass
    this.

    Both spellings work -- bare, or called::

        @mfa_recent_required
        @mfa_recent_required(max_age=60)
        @mfa_recent_required(allow_unenrolled=True)

    ``max_age=None`` means MFA_STEPUP_MAX_AGE, resolved per request so
    override_settings() is honoured.
    """
    if callable(max_age):
        return mfa_recent_required()(max_age)

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            response = _enforce(
                request,
                require_primary_factor=not allow_unenrolled) or _enforce_recent(
                request, max_age, next_url)
            if response is not None:
                return response
            return view_func(request, *args, **kwargs)

        return _wrapped

    return decorator


class MfaRecentRequiredMixin:
    """Class-based-view form of ``mfa_recent_required``.

    Mix in FIRST, so dispatch() runs before the view's own.

    ``mfa_allow_unenrolled = False`` by default -- a factorless user is
    redirected to ``mfa:security_settings`` exactly as ``MfaRequiredMixin``
    would. Set it ``True`` only for the built-in enrollment views, where a
    factorless user must be let through instead. See
    ``mfa_recent_required``'s docstring for the full rationale.
    """

    mfa_stepup_max_age = None
    mfa_stepup_next_url = None
    mfa_allow_unenrolled = False

    def dispatch(self, request, *args, **kwargs):
        response = _enforce(
            request,
            require_primary_factor=not self.mfa_allow_unenrolled) or _enforce_recent(
            request, self.mfa_stepup_max_age, self.mfa_stepup_next_url)
        if response is not None:
            return response
        return super().dispatch(request, *args, **kwargs)
