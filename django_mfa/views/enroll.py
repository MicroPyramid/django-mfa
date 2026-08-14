from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.shortcuts import redirect, render
from django.urls import reverse

from django_mfa import flows
from django_mfa.conf import settings as mfa_settings
from django_mfa.decorators import mfa_recent_required
from django_mfa.models import Authenticator
from django_mfa.views.verify import GENERIC_ERROR, _adapter_or_404


@login_required
@mfa_recent_required(allow_unenrolled=True)
def enroll_factor(request, factor_type):
    adapter = _adapter_or_404(factor_type)
    if not adapter.supports_enroll:
        # Registered and verifiable, but not enrollable (recovery codes are
        # generated at mfa:recovery_codes). available_for() already keeps
        # these off the security page; this covers a hand-typed URL, which
        # would otherwise reach Adapter.begin_enroll and raise
        # NotImplementedError as a 500.
        raise Http404(f"Factor {factor_type!r} is not enrolled this way")
    context = {"adapter": adapter,
               "base_template": mfa_settings.MFA_BASE_TEMPLATE}

    if request.method == "POST":
        try:
            # The adapter call, the normalisation of its three rejection
            # types into one, the session stamp and the factor_added signal
            # are all in flows.attempt_enroll, shared with the JSON API.
            flows.attempt_enroll(request, factor_type, request.POST)
        except flows.FactorRejected:
            # Every rejection renders the exact same generic 400 a wrong code
            # does: a different message (or an unhandled 500) per failure
            # mode would itself be a weak oracle about which check failed.
            context["error_message"] = GENERIC_ERROR
            context.update(adapter.begin_enroll(request))
            return render(request, adapter.enroll_template, context, status=400)

        has_codes = Authenticator.objects.filter(
            user=request.user, type=Authenticator.Type.RECOVERY_CODES).exists()
        if not has_codes:
            return redirect(reverse("mfa:recovery_codes"))
        return redirect(reverse("mfa:security_settings"))

    context.update(adapter.begin_enroll(request))
    return render(request, adapter.enroll_template, context)
