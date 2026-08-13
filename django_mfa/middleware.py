from django.contrib.auth.views import redirect_to_login
from django.shortcuts import resolve_url
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin

from django_mfa import quicklogin, session


class MfaMiddleware(MiddlewareMixin):
    def exempt_paths(self):
        """Paths reachable before verification.

        Built from the registry plus a settings allowlist rather than fully
        hardcoded, so adding a factor does not mean editing this middleware
        — the three-path hardcoded list in the old implementation was
        exactly that maintenance trap.

        ``MFA_EXEMPT_PATHS`` (default ``[]``) covers everything the registry
        can't know about: most importantly a host project's own logout URL.
        Without it, a pending user who cannot complete their second factor
        (lost device, no recovery codes, etc.) has no way out of the
        redirect loop this middleware creates — they can't even log out.
        """
        from django_mfa.conf import settings as mfa_settings
        from django_mfa.registry import registry

        paths = {reverse("mfa:verify")}
        for adapter in registry.all():
            paths.add(reverse("mfa:verify_factor", args=[adapter.type]))
        paths.update(mfa_settings.MFA_EXEMPT_PATHS)
        return paths

    def process_request(self, request):
        if not request.user.is_authenticated:
            return None
        if not session.is_pending(request):
            return None
        if request.path in self.exempt_paths():
            return None
        return redirect_to_login(request.get_full_path(),
                                 resolve_url(reverse("mfa:verify")), "next")

    def process_response(self, request, response):
        """Finish applying the MFA_QUICKLOGIN hint cookie set/cleared by the
        user_logged_in/user_logged_out receivers in signals.py.

        Those receivers can only stash *intent* on the request (no response
        exists yet at signal time -- see set_quicklogin_hint()'s docstring);
        this is the first point in the request lifecycle with both the
        intent and a real response to attach the cookie to.
        """
        user = getattr(request, "_mfa_quicklogin_login", None)
        if user is not None:
            quicklogin.set_hint(response, user, secure=request.is_secure())
        if getattr(request, "_mfa_quicklogin_logout", False):
            quicklogin.clear_hint(response)
        return response
