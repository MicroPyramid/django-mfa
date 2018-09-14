import base64
import codecs
import random
import re

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django_mfa.models import is_mfa_enabled, UserOTP

from . import totp


@login_required
def security_settings(request):
    twofactor_enabled = is_mfa_enabled(request.user)
    return render(request, 'django_mfa/security.html', {"twofactor_enabled": twofactor_enabled})


@login_required
def configure_mfa(request):
    qr_code = None
    base_32_secret_utf8 = None
    if request.method == "POST":
        base_32_secret = base64.b32encode(
            codecs.decode(codecs.encode(
            '{0:020x}'.format(random.getrandbits(80))
            ), 'hex_codec')
        )
        base_32_secret_utf8 = base_32_secret.decode("utf-8")
        totp_obj = totp.TOTP(base_32_secret_utf8)
        qr_code = re.sub(r'=+$', '', totp_obj.provisioning_uri(request.user.email))
    return render(request, 'django_mfa/configure.html', {"qr_code": qr_code, "secret_key": base_32_secret_utf8})


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

    return render(request, 'django_mfa/configure.html', {"is_verified": is_verified, "qr_code": qr_code, "secret_key": base_32_secret})


@login_required
def disable_mfa(request):
    user = request.user
    if not is_mfa_enabled(user):
        return HttpResponseRedirect(reverse("mfa:configure_mfa"))
    if request.method == "POST":
        user_mfa = user.userotp
        user_mfa.delete()
        return HttpResponseRedirect(reverse("mfa:configure_mfa"))
    return render(request, 'django_mfa/disable_mfa.html')


@login_required
def verify_otp(request):
    """
    Verify a OTP request
    """
    ctx = {}

    if request.method == "POST":
        verification_code = request.POST.get('verification_code')

        if verification_code is None:
            ctx['error_message'] = "Missing verification code."
        else:
            otp_ = UserOTP.objects.get(user=request.user)
            totp_ = totp.TOTP(otp_.secret_key)

            is_verified = totp_.verify(verification_code)

            if is_verified:
                request.session['verfied_otp'] = True
                return HttpResponseRedirect(request.POST.get("next", settings.LOGIN_REDIRECT_URL))
            ctx['error_message'] = "Your code is expired or invalid."

    ctx['next'] = request.GET.get('next', settings.LOGIN_REDIRECT_URL)
    return render(request, 'django_mfa/login_verify.html', ctx, status=400)
