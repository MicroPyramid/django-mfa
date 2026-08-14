from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponseForbidden, HttpResponseNotAllowed
from django.shortcuts import get_object_or_404, redirect, render, resolve_url
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from django_mfa import events, flows, policy
from django_mfa.adapters.recovery_codes import RecoveryCodesAdapter
from django_mfa.conf import settings as mfa_settings
from django_mfa.decorators import mfa_recent_required
from django_mfa.models import Authenticator
from django_mfa.registry import registry


@login_required
def security_settings(request):
    context = {
        "enabled_adapters": registry.enabled_for(request.user),
        "available_adapters": registry.available_for(request.user),
        # Individual Authenticator rows (not just the distinct types
        # enabled_adapters above gives) -- this is what lets the template
        # list, and offer removal of, each authenticator separately (e.g. a
        # user with three security keys can tell them apart by name/date,
        # and remove exactly one). See security.html.
        "authenticators": Authenticator.objects.filter(
            user=request.user).order_by("type", "created_at"),
        "recovery_codes_remaining": RecoveryCodesAdapter().remaining(request.user),
        "owned_by_enterprise": mfa_settings.MFA_OWNED_BY_ENTERPRISE,
        "base_template": mfa_settings.MFA_BASE_TEMPLATE,
        # True only when this user is *both* required to hold a factor and
        # holds none -- i.e. exactly when MfaMiddleware walled them here.
        # has_primary_factor, not primary_enabled_for: only the yes/no answer
        # is needed here, and this view is the one every enrollment-required
        # user lands back on after every action, so it runs on every one of
        # those requests. Same three-part order as the middleware's rung:
        # policy.resolve() gates the other two so MFA_REQUIRED = False costs
        # nothing, and has_primary_factor() then runs before
        # mfa_required_for() so the exemption lookup inside it only runs for
        # a user actually about to be walled.
        "mfa_enrollment_required": bool(
            policy.resolve()
            and not registry.has_primary_factor(request.user)
            and policy.mfa_required_for(request.user)),
        # None unless this user would be walled but is not yet. The template
        # can say "you have N days"; nothing here enforces against it --
        # see policy.GraceState.
        "grace": policy.grace_state(request.user),
    }
    return render(request, "django_mfa/security.html", context)


@login_required
@mfa_recent_required(allow_unenrolled=True)
def recovery_codes(request):
    """Show the user their recovery codes.

    Codes are hashed at rest (see RecoveryCodesAdapter) and generate()
    returns plaintext exactly once. That plaintext is used ONLY to render
    this response -- it must never be written to the session, the database,
    or anywhere else that outlives this request/response cycle. Once an
    Authenticator row already exists, there is nothing left to show: the
    plaintext is gone for good, and this renders with codes=None. Downloading
    the codes is handled client-side (see recovery_codes.html) by building a
    file from the codes already in the rendered page, precisely so the
    server never needs to retain them.
    """
    has_codes = Authenticator.objects.filter(
        user=request.user, type=Authenticator.Type.RECOVERY_CODES).exists()
    codes = None
    if not has_codes:
        codes = RecoveryCodesAdapter().generate(request.user)
        events.factor_added.send_robust(
            sender=RecoveryCodesAdapter, user=request.user,
            authenticator=Authenticator.objects.get(
                user=request.user, type=Authenticator.Type.RECOVERY_CODES),
            request=request)
    next_url = resolve_url(settings.LOGIN_REDIRECT_URL)
    return render(request, "django_mfa/recovery_codes.html", {
        "codes": codes,
        "next_url": next_url,
        "base_template": mfa_settings.MFA_BASE_TEMPLATE,
    })


@login_required
@mfa_recent_required(allow_unenrolled=True)
def manage_factors(request):
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    # A non-integer pk makes the ORM raise ValueError before it can raise
    # DoesNotExist, which get_object_or_404 does not catch -- so an
    # unparseable pk has to be turned into the same 404 a missing or
    # someone-else's pk gets, rather than a 500.
    try:
        authenticator = get_object_or_404(
            Authenticator, pk=int(request.POST.get("pk", "")),
            user=request.user)
    except (TypeError, ValueError, OverflowError):
        # ValueError/TypeError: int() rejects it outright. OverflowError: it
        # parses but exceeds what the column can hold, which only surfaces
        # when the query executes.
        raise Http404("No such authenticator") from None
    if (authenticator.type == Authenticator.Type.WEBAUTHN
            and mfa_settings.MFA_OWNED_BY_ENTERPRISE):
        return HttpResponseForbidden(_(
            "This security key is managed by your organization and cannot "
            "be removed here."))

    flows.remove_factor(request, authenticator)
    return redirect(reverse("mfa:security_settings"))
