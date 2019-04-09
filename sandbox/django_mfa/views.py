import base64
import codecs
import random
import hashlib
import re
import os
from django.http import HttpResponse
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect
from django_mfa.models import *
from django.contrib.auth.models import User
from . import totp
import random
import string
from django.conf import settings


@login_required
def security_settings(request):
    twofactor_enabled = is_mfa_enabled(request.user)
    backup_codes = UserRecoveryCodes.objects.filter(
        user=UserOTP.objects.filter(user=request.user).first()).all()
    return render(request, 'django_mfa/security.html', {"backup_codes": backup_codes, "twofactor_enabled": twofactor_enabled})


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
        qr_code = re.sub(
            r'=+$', '', totp_obj.provisioning_uri(request.user.username, issuer_name=issuer_name))

    return render(request, 'django_mfa/configure.html', {"qr_code": qr_code, "secret_key": base_32_secret_utf8})


@login_required
def enable_mfa(request):
    if is_mfa_enabled(request.user):
        return HttpResponseRedirect(reverse("mfa:disable_mfa"))
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
            messages.success(
                request, "You have successfully enabled multi-factor authentication on your account.")
            response = redirect(reverse('mfa:recovery_codes'))
            return response
        else:
            totp_obj = totp.TOTP(base_32_secret)
            qr_code = totp_obj.provisioning_uri(request.user.email)

    return render(request, 'django_mfa/configure.html', {"is_verified": is_verified, "qr_code": qr_code, "secret_key": base_32_secret})


def _generate_cookie_salt(user):
    try:
        otp_ = UserOTP.objects.get(user=user)
    except UserOTP.DoesNotExist:
        return None
    # out of paranoia only use half the secret to generate the salt
    uselen = int(len(otp_.secret_key) / 2)
    half_secret = otp_.secret_key[:uselen]
    m = hashlib.sha256()
    m.update(half_secret.encode("utf-8"))
    cookie_salt = m.hexdigest()
    return cookie_salt


MFA_COOKIE_PREFIX = "RMB_"


# update Remember-My-Browser cookie
def update_rmb_cookie(request, response):
    try:
        remember_my_browser = settings.MFA_REMEMBER_MY_BROWSER
        remember_days = settings.MFA_REMEMBER_DAYS
    except:
        remember_my_browser = False
    if remember_my_browser:
        # better not to reveal the username.  Revealing the number seems harmless
        cookie_name = MFA_COOKIE_PREFIX + str(request.user.pk)
        cookie_salt = _generate_cookie_salt(request.user)
        response.set_signed_cookie(cookie_name, True, salt=cookie_salt, max_age=remember_days * 24 * 3600,
                                   secure=(not settings.DEBUG), httponly=True)
    return response


# verify Remember-My-Browser cookie
# returns True if browser is trusted and no code verification needed
def verify_rmb_cookie(request):
    try:
        remember_my_browser = settings.MFA_REMEMBER_MY_BROWSER
        max_cookie_age = settings.MFA_REMEMBER_DAYS * 24 * 3600
    except:
        return False
    if not remember_my_browser:
        return False
    else:
        cookie_name = MFA_COOKIE_PREFIX + str(request.user.pk)
        cookie_salt = _generate_cookie_salt(request.user)
        cookie_value = request.get_signed_cookie(
            cookie_name, False, max_age=max_cookie_age, salt=cookie_salt)
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
        messages.success(
            request, "You have successfully disabled multi-factor authentication on your account.")
        response = redirect(reverse('mfa:configure_mfa'))
        return delete_rmb_cookie(request, response)
    return render(request, 'django_mfa/disable_mfa.html')


@login_required
def verify_otp(request):
    """
    Verify a OTP request
    """
    ctx = {}
    if request.method == 'GET':
        ctx['next'] = request.GET.get('next', settings.LOGIN_REDIRECT_URL)
        return render(request, 'django_mfa/login_verify.html', ctx)

    if request.method == "POST":
        verification_code = request.POST.get('verification_code')

        if verification_code is None:
            ctx['error_message'] = "Missing verification code."

        else:
            user_recovery_codes = UserRecoveryCodes.objects.values_list('secret_code', flat=True).filter(
                user=UserOTP.objects.get(user=request.user.id))
            if verification_code in user_recovery_codes:
                UserRecoveryCodes.objects.filter(user=UserOTP.objects.get(
                    user=request.user.id), secret_code=verification_code).delete()
                is_verified = True
            else:
                otp_ = UserOTP.objects.get(user=request.user)
                totp_ = totp.TOTP(otp_.secret_key)

                is_verified = totp_.verify(verification_code)

            if is_verified:
                request.session['verfied_otp'] = True
                response = redirect(request.POST.get(
                    "next", settings.LOGIN_REDIRECT_URL))
                return update_rmb_cookie(request, response)
            ctx['error_message'] = "Your code is expired or invalid."

    ctx['next'] = request.GET.get('next', settings.LOGIN_REDIRECT_URL)
    return render(request, 'django_mfa/login_verify.html', ctx, status=400)


def generate_user_recovery_codes(user_id):
    no_of_recovery_codes = 10
    size_of_recovery_code = 16
    recovery_codes_list = []
    chars = string.ascii_uppercase + string.digits + string.ascii_lowercase
    while(no_of_recovery_codes > 0):
        code = ''.join(random.choice(chars)
                       for _ in range(size_of_recovery_code))
        Total_recovery_codes = UserRecoveryCodes.objects.values_list('secret_code', flat=True).filter(
            user=UserOTP.objects.get(user=user_id))
        if code not in Total_recovery_codes:
            no_of_recovery_codes = no_of_recovery_codes - 1
            UserRecoveryCodes.objects.create(
                user=UserOTP.objects.get(user=user_id), secret_code=code)
            recovery_codes_list.append(code)
    return recovery_codes_list


@login_required
def recovery_codes(request):
    if request.method == "GET":
        if UserOTP.objects.filter(user=request.user.id).exists():
            if UserRecoveryCodes.objects.filter(user=UserOTP.objects.get(user=request.user.id)).exists():
                codes = UserRecoveryCodes.objects.values_list('secret_code', flat=True).filter(
                    user=UserOTP.objects.get(user=request.user.id))
            else:
                codes = generate_user_recovery_codes(request.user.id)
            next_url = settings.LOGIN_REDIRECT_URL
            return render(request, "django_mfa/recovery_codes.html", {"codes": codes, "next_url": next_url})
        else:
            return HttpResponse("please enable twofactor_authentication!")


@login_required
def recovery_codes_download(request):
    user_id = request.user.id
    codes_list = []
    codes = UserRecoveryCodes.objects.values_list('secret_code', flat=True).filter(
        user=UserOTP.objects.get(user=request.user.id))
    for i in codes:
        codes_list.append(i)
        codes_list.append("\n")
    response = HttpResponse(
        codes_list, content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename=%s' % 'recovery_codes.txt'
    return response
