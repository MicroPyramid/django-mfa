from django.shortcuts import render
import totp
import base64
from django.contrib.auth.decorators import login_required
from django_mfa.models import *
from django.http import HttpResponseRedirect


@login_required
def security_settings(request):
    return render(request, 'security.html')


@login_required
def configure_mfa(request):
    qr_code = None
    if request.method == "POST":
        base_32_secret = base64.b32encode(request.user.email)
        totp_obj = totp.TOTP(base_32_secret)
        qr_code = totp_obj.provisioning_uri(request.user.email)
        UserOTP.objects.get_or_create(otp_type=request.POST["otp_type"],
                                      user=request.user,
                                      secret_key=base_32_secret)
    return render(request, 'configure.html', {"qr_code": qr_code})


@login_required
def enable_mfa(request):
    if request.method == "POST":
        otp_obj = UserOTP.objects.filter(user=request.user).first()
        totp_obj = totp.TOTP(otp_obj.secret_key)
        is_verified = totp_obj.verify(request.POST["verification_code"])
        if is_verified:
            request.session['verfied_otp'] = True

    return render(request, 'configure.html', {"is_verified": is_verified})


@login_required
def disable_mfa(request):
    user = request.user
    if not is_mfa_enabled(user):
        reverse("mfa:configure_mfa")
    if request.method == "POST":
        user_mfa = user.userotp
        user_mfa.delete()
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
            return HttpResponseRedirect(request.POST["next"])
        ctx['error_message'] = "Your code is expired or invalid."
    ctx['next_url'] = request.GET["next"]
    return render(request, 'login_verify.html', ctx)
