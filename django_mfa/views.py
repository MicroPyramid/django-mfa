import base64
import codecs
import random
import hashlib
import re
from django.http import HttpResponse, JsonResponse
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect
from django_mfa.models import *
from . import totp
import string
from django.contrib.auth import get_user_model


@login_required
def security_settings(request):
    show_disable = False
    twofactor_enabled = is_mfa_enabled(request.user)
    if not settings.ENFORCE_MFA:
        show_disable = True
    backup_codes = UserRecoveryCodes.objects.filter(
        user=UserOTP.objects.filter(user=request.user).first()
    ).all()
    return render(
        request,
        "django_mfa/security.html",
        {
            "show_disable": show_disable,
            "backup_codes": backup_codes,
            "twofactor_enabled": twofactor_enabled,
        },
    )


@login_required
def configure_mfa(request):
    qr_code = None
    base_32_secret_utf8 = None
    if request.method == "POST":
        base_32_secret = base64.b32encode(
            codecs.decode(
                codecs.encode("{0:020x}".format(random.getrandbits(80))), "hex_codec"
            )
        )
        base_32_secret_utf8 = base_32_secret.decode("utf-8")
        totp_obj = totp.TOTP(base_32_secret_utf8)

        try:
            issuer_name = settings.MFA_ISSUER_NAME
        except:
            issuer_name = None
        qr_code = re.sub(
            r"=+$",
            "",
            totp_obj.provisioning_uri(request.user.username, issuer_name=issuer_name),
        )

    return render(
        request,
        "django_mfa/configure.html",
        {"qr_code": qr_code, "secret_key": base_32_secret_utf8},
    )


@login_required
def enable_mfa(request):
    if is_mfa_enabled(request.user):
        return HttpResponseRedirect(reverse("mfa:security_settings"))
    qr_code = None
    base_32_secret = None
    is_verified = False
    if request.method == "POST":
        base_32_secret = request.POST["secret_key"]
        totp_obj = totp.TOTP(request.POST["secret_key"])
        is_verified = totp_obj.verify(request.POST["verification_code"])
        if is_verified:
            request.session["verfied_otp"] = True
            UserOTP.objects.get_or_create(
                otp_type=request.POST["otp_type"],
                user=request.user,
                secret_key=request.POST["secret_key"],
            )
            messages.success(
                request,
                "You have successfully enabled multi-factor authentication on your account.",
            )
            response = redirect(reverse("mfa:recovery_codes"))
            return response
        else:
            totp_obj = totp.TOTP(base_32_secret)
            qr_code = totp_obj.provisioning_uri(request.user.email)

    return render(
        request,
        "django_mfa/configure.html",
        {"is_verified": is_verified, "qr_code": qr_code, "secret_key": base_32_secret},
    )


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
        response.set_signed_cookie(
            cookie_name,
            True,
            salt=cookie_salt,
            max_age=remember_days * 24 * 3600,
            secure=(not settings.DEBUG),
            httponly=True,
        )
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
            cookie_name, False, max_age=max_cookie_age, salt=cookie_salt
        )
        # if the cookie value is True and the signature is good than the browser can be trusted
        return cookie_value


def delete_rmb_cookie(request, response):
    cookie_name = MFA_COOKIE_PREFIX + str(request.user.pk)
    response.delete_cookie(cookie_name)
    return response


@login_required
def disable_mfa(request):
    ctx = {}
    if not is_mfa_enabled(request.user):
        return HttpResponseRedirect(reverse("mfa:configure_mfa"))
    if request.method == "POST":
        verification_code = request.POST.get("verification_code", None)

        if verification_code is None:
            ctx["error_message"] = "Missing verification code."

        else:
            usr_rc_code = UserRecoveryCodes.objects.filter(
                user=UserOTP.objects.get(user=request.user.id),
                secret_code=verification_code,
            )
            if usr_rc_code.exists():
                usr_rc_code.first().delete()
                is_verified = True
            else:
                otp_ = UserOTP.objects.get(user=request.user)
                totp_ = totp.TOTP(otp_.secret_key)
                is_verified = totp_.verify(verification_code)

            if is_verified:
                user_mfa = request.user.userotp
                user_mfa.delete()
                messages.success(
                    request,
                    "You have successfully disabled multi-factor authentication on your account.",
                )
                response = redirect(reverse("mfa:configure_mfa"))
                return delete_rmb_cookie(request, response)
            ctx["error_message"] = "Your code is expired or invalid."
    return render(request, "django_mfa/disable_mfa.html", ctx)


@login_required
def verify_otp(request):
    """
    Verify a OTP request
    """
    ctx = {}
    if request.method == "GET":
        ctx["next"] = request.GET.get("next", settings.LOGIN_REDIRECT_URL)
        return render(request, "django_mfa/login_verify.html", ctx)

    if request.method == "POST":
        verification_code = request.POST.get("verification_code")

        if verification_code is None:
            ctx["error_message"] = "Missing verification code."

        else:
            usr_rc_code = UserRecoveryCodes.objects.filter(
                user=UserOTP.objects.get(user=request.user.id),
                secret_code=verification_code,
            )
            if usr_rc_code.exists():
                usr_rc_code.first().delete()
                is_verified = True
            else:
                otp_ = UserOTP.objects.get(user=request.user)
                totp_ = totp.TOTP(otp_.secret_key)
                is_verified = totp_.verify(verification_code)

            if is_verified:
                request.session["verfied_otp"] = True
                response = redirect(
                    request.POST.get("next", settings.LOGIN_REDIRECT_URL)
                )
                return update_rmb_cookie(request, response)
            ctx["error_message"] = "Your code is expired or invalid."

    ctx["next"] = request.GET.get("next", settings.LOGIN_REDIRECT_URL)
    return render(request, "django_mfa/login_verify.html", ctx, status=400)


def generate_user_recovery_codes(user_id):
    no_of_recovery_codes = 10
    size_of_recovery_code = 16
    recovery_codes_list = []
    chars = string.ascii_uppercase + string.digits + string.ascii_lowercase
    while no_of_recovery_codes > 0:
        code = "".join(random.choice(chars) for _ in range(size_of_recovery_code))
        Total_recovery_codes = UserRecoveryCodes.objects.values_list(
            "secret_code", flat=True
        ).filter(user=UserOTP.objects.get(user=user_id))
        if code not in Total_recovery_codes:
            no_of_recovery_codes = no_of_recovery_codes - 1
            UserRecoveryCodes.objects.create(
                user=UserOTP.objects.get(user=user_id), secret_code=code
            )
            recovery_codes_list.append(code)
    return recovery_codes_list


@login_required
def recovery_codes(request):
    if request.method == "GET":
        if UserOTP.objects.filter(user=request.user.id).exists():
            if UserRecoveryCodes.objects.filter(
                user=UserOTP.objects.get(user=request.user.id)
            ).exists():
                user_codes = UserRecoveryCodes.objects.values_list(
                    "secret_code", flat=True
                ).filter(user=UserOTP.objects.get(user=request.user.id))
            else:
                user_codes = generate_user_recovery_codes(request.user.id)
            next_url = settings.LOGIN_REDIRECT_URL
        else:
            user_codes = []
            next_url = reverse("mfa:security_settings")
        return render(
            request,
            "django_mfa/recovery_codes.html",
            {"user_codes": user_codes, "next_url": next_url},
        )


@login_required
def recovery_codes_download(request):
    codes_list = []
    filename = "recoverycodes.txt"
    if request.user.username:
        filename = str(request.user.username) + "_recoverycodes.txt"
    usercodes = UserRecoveryCodes.objects.values_list("secret_code", flat=True).filter(
        user=UserOTP.objects.get(user=request.user.id)
    )
    for usr_code in usercodes:
        codes_list.append(usr_code)
        codes_list.append("\n")
    response = HttpResponse(codes_list, content_type="text/plain")
    response["Content-Disposition"] = "attachment; filename=%s" % filename
    return response


def admin_disable_mfa(user_id):
    AuthUser = get_user_model()
    user = AuthUser.objects.filter(id=user_id)
    if user.exists():
        if UserOTP.objects.filter(user_id=user_id):
            user_mfa = user.first().userotp
            user_mfa.delete()
            data = {
                "message": "Mfa successfully disbaled for user ",
                "email": user.first().email,
            }
        else:
            data = {
                "message": "Mfa is not Enabled for given user ",
                "email": user.first().email,
            }
    else:
        data = {"message": "User not found"}
    return JsonResponse(data)
