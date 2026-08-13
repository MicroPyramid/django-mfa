from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.urls import reverse

from django_mfa.conf import settings as mfa_settings
from django_mfa.registry import registry


@login_required
def verify(request):
    adapters = registry.enabled_for(request.user)
    if len(adapters) == 1:
        return redirect(reverse("mfa:verify_factor", args=[adapters[0].type]))
    return render(request, "django_mfa/picker.html", {
        "adapters": adapters,
        "base_template": mfa_settings.MFA_BASE_TEMPLATE,
    })
