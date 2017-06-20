from django.shortcuts import render
from . import totp
import base64
from django.contrib.auth.decorators import login_required
from django_mfa.models import *
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.conf import settings


@login_required
def security_settings(request):
    twofactor_enabled = is_mfa_enabled(request.user)
    return render(request, 'security.html', {"twofactor_enabled": twofactor_enabled})


@login_required
def configure_mfa(request):
    qr_code = None
    base_32_secret = None
    if request.method == "POST":
        base_32_secret = base64.b32encode(bytes(request.user.email, 'utf-8'))
        totp_obj = totp.TOTP(base_32_secret.decode("utf-8"))
        qr_code = totp_obj.provisioning_uri(request.user.email)

    return render(request, 'configure.html', {"qr_code": qr_code, "secret_key": base_32_secret})


@login_required
def enable_mfa(request):
    qr_code = None
    base_32_secret = None
    is_verified = False
    if request.method == "POST":
        base_32_secret = request.POST['secret_key']
        totp_obj = totp.TOTP(request.POST['secret_key'])
        is_verified = totp_obj.verify(request.POST["verification_code"])
        if is_verified:
            request.session['verfied_otp'] = True
            UserOTP.objects.get_or_create(otp_type=request.POST["otp_type"],
                                          user=request.user,
                                          secret_key=request.POST['secret_key'])
        else:
            totp_obj = totp.TOTP(base_32_secret)
            qr_code = totp_obj.provisioning_uri(request.user.email)

    return render(request, 'configure.html', {"is_verified": is_verified, "qr_code": qr_code, "secret_key": base_32_secret})


@login_required
def disable_mfa(request):
    user = request.user
    if not is_mfa_enabled(user):
        return HttpResponseRedirect(reverse("mfa:configure_mfa"))
    if request.method == "POST":
        user_mfa = user.userotp
        user_mfa.delete()
        return HttpResponseRedirect(reverse("mfa:configure_mfa"))
    return render(request, 'disable_mfa.html')


@login_required
def verify_otp(request):
    ctx = {}
    if request.method == "POST":
        otp_obj = UserOTP.objects.filter(user=request.user).first()
        totp_obj = totp.TOTP(otp_obj.secret_key)
        is_verified = totp_obj.verify(request.POST["verification_code"])
        if is_verified:
            request.session['verfied_otp'] = True
            return HttpResponseRedirect(request.POST.get("next", settings.LOGIN_REDIRECT_URL))
        ctx['error_message'] = "Your code is expired or invalid."
    ctx['next'] = request.GET.get('next') or settings.LOGIN_REDIRECT_URL
    return render(request, 'login_verify.html', ctx)
