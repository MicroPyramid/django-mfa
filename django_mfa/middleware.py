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

        Deliberately does NOT include the enroll pages. See
        enrollment_exempt_paths() below for why the two sets must stay
        separate.
        """
        from django_mfa.conf import settings as mfa_settings
        from django_mfa.registry import registry

        paths = {reverse("mfa:verify")}
        for adapter in registry.all():
            paths.add(reverse("mfa:verify_factor", args=[adapter.type]))
        paths.update(mfa_settings.MFA_EXEMPT_PATHS)
        return paths

    def enrollment_exempt_paths(self):
        """Paths reachable while a REQUIRED user has not enrolled anything.

        A different set from exempt_paths() above, and merging the two is a
        vulnerability rather than a tidy-up: views.enroll.enroll_factor calls
        session.mark_verified() on success, so a *pending* user allowed onto
        an enroll page could enroll a fresh TOTP with a secret of their own
        choosing and satisfy the session without ever presenting the factor
        they already hold. The pending set must exclude enrollment; this set
        is almost entirely enrollment.

        MFA_EXEMPT_PATHS applies here too: without it a required user who
        cannot enroll (no phone, no security key to hand) is trapped with no
        way even to log out.
        """
        from django_mfa.conf import settings as mfa_settings
        from django_mfa.registry import registry

        paths = {reverse("mfa:security_settings"), reverse("mfa:recovery_codes")}
        for adapter in registry.all():
            if adapter.supports_enroll:
                paths.add(reverse("mfa:enroll_factor", args=[adapter.type]))
        paths.update(mfa_settings.MFA_EXEMPT_PATHS)
        return paths

    @staticmethod
    def _is_exempt(path, paths):
        """One comparison for both sets, so they cannot come to disagree
        about what counts as the same path."""
        return path in paths

    def process_request(self, request):
        from django_mfa import policy
        from django_mfa.registry import registry

        if not request.user.is_authenticated:
            return None

        if session.is_pending(request):
            if self._is_exempt(request.path, self.exempt_paths()):
                return None
            return redirect_to_login(request.get_full_path(),
                                     resolve_url(reverse("mfa:verify")), "next")

        # A required user with no primary factor is never *pending*:
        # signals.stamp_pending_verification only stamps a session when
        # registry.primary_enabled_for() is non-empty. That is precisely why
        # this second rung exists -- without it, "MFA is required" would have
        # no effect on the one user it needs to reach.
        #
        # has_primary_factor(), not primary_enabled_for(): this rung only
        # needs the yes/no answer, and primary_enabled_for() would run one
        # .exists() query per registered adapter (via enabled_for()) on every
        # single authenticated request just to build a list this branch
        # immediately discards.
        #
        # policy.resolve() gates the other two so MFA_REQUIRED = False (the
        # default) still costs nothing: has_primary_factor() is a query, so
        # it cannot be the unconditional first operand or every authenticated
        # request pays it even with MFA_REQUIRED off. Once past that gate,
        # has_primary_factor() runs before mfa_required_for() so the
        # exemption lookup inside mfa_required_for() runs only for a user who
        # is actually about to be walled, not for every enrolled user this
        # policy applies to.
        if (policy.resolve()
                and not registry.has_primary_factor(request.user)
                and policy.mfa_required_for(request.user)):
            if self._is_exempt(request.path, self.enrollment_exempt_paths()):
                return None
            return redirect_to_login(
                request.get_full_path(),
                resolve_url(reverse("mfa:security_settings")), "next")

        return None

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
