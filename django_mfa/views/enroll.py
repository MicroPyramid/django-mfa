from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.shortcuts import redirect, render
from django.urls import reverse

from django_mfa import session
from django_mfa.conf import settings as mfa_settings
from django_mfa.models import Authenticator
from django_mfa.views.verify import GENERIC_ERROR, _adapter_or_404


@login_required
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
            adapter.complete_enroll(request, request.POST)
        except (ValueError, TypeError, KeyError):
            # ValueError: the adapter's own "this ceremony/code is invalid"
            #   signal (e.g. TOTP's wrong code, or a stale/replayed WebAuthn
            #   registration challenge).
            # TypeError: a tampered WebAuthn credential payload -- valid
            #   JSON, but not the mapping shape fido2 expects (e.g. a JSON
            #   array), which fido2's own parsing rejects with TypeError
            #   rather than ValueError.
            # KeyError / MultiValueDictKeyError (a KeyError subclass): a
            #   required POST field is simply missing -- `secret_key` for
            #   TOTP, `credential` for WebAuthn.
            # All three must render the exact same generic 400 a wrong code
            # does: a different message (or an unhandled 500) per failure
            # mode would itself be a weak oracle about which check failed.
            context["error_message"] = GENERIC_ERROR
            context.update(adapter.begin_enroll(request))
            return render(request, adapter.enroll_template, context, status=400)

        # Enrolling a factor satisfies this session's requirement — the user
        # just proved possession.
        session.mark_verified(request, factor_type)

        has_codes = Authenticator.objects.filter(
            user=request.user, type=Authenticator.Type.RECOVERY_CODES).exists()
        if not has_codes:
            return redirect(reverse("mfa:recovery_codes"))
        return redirect(reverse("mfa:security_settings"))

    context.update(adapter.begin_enroll(request))
    return render(request, adapter.enroll_template, context)
