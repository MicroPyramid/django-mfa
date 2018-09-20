import base64
import codecs
import random
import re

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect
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

        try:
            issuer_name = settings.MFA_ISSUER_NAME
        except:
            issuer_name = None
        qr_code = re.sub(r'=+$', '', totp_obj.provisioning_uri(request.user.username, issuer_name=issuer_name))

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
            messages.success(request, "You have successfully enabled multi-factor authentication on your account.")
            response = redirect(settings.LOGIN_REDIRECT_URL)
            return response
        else:
            totp_obj = totp.TOTP(base_32_secret)
            qr_code = totp_obj.provisioning_uri(request.user.email)

    return render(request, 'django_mfa/configure.html', {"is_verified": is_verified, "qr_code": qr_code, "secret_key": base_32_secret})


MFA_COOKIE_PREFIX="RMB_"
# update Remember-My-Browser cookie
def update_rmb_cookie(request, response):
    try:
        remember_my_browser = settings.MFA_REMEMBER_MY_BROWSER
        remember_days = settings.MFA_REMEMBER_DAYS
        cookie_salt = settings.MFA_COOKIE_SALT
    except:
        remember_my_browser = False
    if remember_my_browser:
        # better not to reveal the username.  Revealing the number seems harmless
        cookie_name = MFA_COOKIE_PREFIX + str(request.user.pk)
        response.set_signed_cookie(cookie_name, True, salt=cookie_salt, max_age=remember_days*24*3600,
                                   secure=(not settings.DEBUG), httponly=True)
    return response


# verify Remember-My-Browser cookie
# returns True if browser is trusted and no code verification needed
def verify_rmb_cookie(request):
    try:
        remember_my_browser = settings.MFA_REMEMBER_MY_BROWSER
        max_cookie_age = settings.MFA_REMEMBER_DAYS*24*3600
        cookie_salt = settings.MFA_COOKIE_SALT
    except:
        return False
    if not remember_my_browser:
        return False
    else:
        cookie_name = MFA_COOKIE_PREFIX + str(request.user.pk)
        cookie_value = request.get_signed_cookie(cookie_name, False, max_age=max_cookie_age, salt=cookie_salt)
        # if the cookie value is True and the signature is good than the browser can be trusted
        return cookie_value


def delete_rmb_cookie(request, response):
    cookie_name = MFA_COOKIE_PREFIX + str(request.user.pk)
    response.delete_cookie(cookie_name)
    return response


@login_required
def disable_mfa(request):
    user = request.user
    if not is_mfa_enabled(user):
        return HttpResponseRedirect(reverse("mfa:configure_mfa"))
    if request.method == "POST":
        user_mfa = user.userotp
        user_mfa.delete()
        messages.success(request, "You have successfully disabled multi-factor authentication on your account.")
        response = redirect(settings.LOGIN_REDIRECT_URL)
        return delete_rmb_cookie(request, response)
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
                response = redirect(request.POST.get("next", settings.LOGIN_REDIRECT_URL))
                return update_rmb_cookie(request, response)
            ctx['error_message'] = "Your code is expired or invalid."

    ctx['next'] = request.GET.get('next', settings.LOGIN_REDIRECT_URL)
    return render(request, 'django_mfa/login_verify.html', ctx, status=400)
