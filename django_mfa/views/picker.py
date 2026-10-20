from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render, resolve_url
from django.urls import reverse

from django_mfa import session
from django_mfa.conf import settings as mfa_settings
from django_mfa.registry import registry
from django_mfa.views.verify import safe_next_or_none


@login_required
def verify(request):
    adapters = registry.enabled_for(request.user)
    # `next` has to survive both branches. Without it a single-factor user is
    # sent to LOGIN_REDIRECT_URL after logging in rather than to the page they
    # asked for, and the step-up gate (decorators.mfa_recent_required) can
    # never return anyone to the view it interrupted.
    next_url = safe_next_or_none(request)
    if not adapters:
        # Nothing to verify with: every factor went after this session was
        # stamped pending at login (manage.py mfa_reset, or MFA_FACTORS
        # narrowed). A fresh login would not be challenged at all, since the
        # login receiver only stamps a user who holds a primary factor, so the
        # stale stamp is dropped instead of rendering a picker with no choices
        # and no way out. MfaMiddleware then decides from what the user holds
        # now; under MFA_REQUIRED that is the enrollment wall.
        if session.is_pending(request):
            session.reset(request)
        return redirect(next_url or resolve_url(settings.LOGIN_REDIRECT_URL))
    if len(adapters) == 1:
        url = reverse("mfa:verify_factor", args=[adapters[0].type])
        if next_url:
            url = f"{url}?{urlencode({'next': next_url})}"
        return redirect(url)
    return render(request, "django_mfa/picker.html", {
        "adapters": adapters,
        "next": next_url,
        "base_template": mfa_settings.MFA_BASE_TEMPLATE,
    })
