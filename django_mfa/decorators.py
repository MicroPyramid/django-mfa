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


def _enforce(request):
    """Return a redirect response, or None to let the request through."""
    from django_mfa.registry import registry

    user = request.user
    if not user.is_authenticated:
        return redirect_to_login(request.get_full_path())
    if session.is_pending(request):
        return redirect_to_login(request.get_full_path(),
                                 resolve_url(reverse("mfa:verify")), "next")
    if not registry.has_primary_factor(user):
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
