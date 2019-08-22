import base64
import codecs
import random
import hashlib
import re
import string
from django.http import HttpResponse, HttpResponseRedirect
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, resolve_url, get_object_or_404
from django_mfa.models import *
from . import totp
from django.views.generic import FormView, ListView, TemplateView
from django.contrib.auth import load_backend
from django.contrib import auth, messages
from django.urls import reverse, reverse_lazy
from django.utils.http import is_safe_url
from django.utils.translation import ugettext as _
from u2flib_server import u2f
from .forms import *


class OriginMixin(object):
    def get_origin(self):
        return '{scheme}://{host}'.format(
            scheme=self.request.scheme,
            host=self.request.get_host(),
        )


@login_required
def security_settings(request):
    twofactor_enabled = is_mfa_enabled(request.user)
    u2f_enabled = is_u2f_enabled(request.user)
    backup_codes = UserRecoveryCodes.objects.filter(
        user=UserOTP.objects.filter(user=request.user).first()).all()
    return render(request, 'django_mfa/security.html', {"prev_url": settings.LOGIN_REDIRECT_URL, "backup_codes": backup_codes, "u2f_enabled": u2f_enabled, "twofactor_enabled": twofactor_enabled})


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
    user = request.user
    if is_mfa_enabled(user):
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
            response = redirect(reverse("mfa:recovery_codes"))
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
def verify_second_factor_totp(request):
    """
    Verify a OTP request
    """
    ctx = {}
    if request.method == 'GET':
        ctx['next'] = request.GET.get('next', settings.LOGIN_REDIRECT_URL)
        return render(request, 'django_mfa/verify_second_factor_mfa.html', ctx)

    if request.method == "POST":
        verification_code = request.POST.get('verification_code')
        ctx['next'] = request.POST.get("next", settings.LOGIN_REDIRECT_URL)

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
                request.session['verfied_u2f'] = True
                response = redirect(request.POST.get(
                    "next", settings.LOGIN_REDIRECT_URL))
                return update_rmb_cookie(request, response)
            ctx['error_message'] = "Your code is expired or invalid."
    else:
        ctx['next'] = request.GET.get('next', settings.LOGIN_REDIRECT_URL)

    return render(request, 'django_mfa/verify_second_factor_mfa.html', ctx, status=400)


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
        if is_mfa_enabled(request.user):
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
def verify_second_factor(request):
    if request.method == "GET":
        twofactor_enabled = is_mfa_enabled(request.user)
        u2f_enabled = is_u2f_enabled(request.user)
        if twofactor_enabled or u2f_enabled:
            return render(request, 'django_mfa/verify_second_factor.html', {"u2f_enabled": u2f_enabled, "twofactor_enabled": twofactor_enabled})


@login_required
def recovery_codes_download(request):
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


class AddKeyView(OriginMixin, FormView):
    template_name = 'u2f/add_key.html'
    form_class = KeyRegistrationForm
    success_url = reverse_lazy('mfa:u2f_keys')

    def dispatch(self, request, *args, **kwargs):
        return super(AddKeyView, self).dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super(AddKeyView, self).get_form_kwargs()
        kwargs.update(
            user=self.request.user,
            request=self.request,
            appId=self.get_origin(),
        )
        return kwargs

    def get_context_data(self, **kwargs):
        kwargs = super(AddKeyView, self).get_context_data(**kwargs)
        request = u2f.begin_registration(self.get_origin(), [
            key.to_json() for key in self.request.user.u2f_keys.all()
        ])
        self.request.session['u2f_registration_request'] = request
        kwargs['registration_request'] = request
        return kwargs

    def form_valid(self, form):
        request = self.request.session['u2f_registration_request']
        response = form.cleaned_data['response']
        del self.request.session['u2f_registration_request']
        device, attestation_cert = u2f.complete_registration(request, response)
        self.request.user.u2f_keys.create(
            public_key=device['publicKey'],
            key_handle=device['keyHandle'],
            app_id=device['appId'],
        )
        self.request.session['verfied_u2f'] = True
        messages.success(self.request, _("Key added."))
        return super(AddKeyView, self).form_valid(form)

    def get_success_url(self):
        if 'next' in self.request.GET and is_safe_url(self.request.GET['next']):
            return self.request.GET['next']
        else:
            return super(AddKeyView, self).get_success_url()


class VerifySecondFactorView(OriginMixin, TemplateView):
    template_name = 'u2f/verify_second_factor_u2f.html'

    @property
    def form_classes(self):
        ret = {}
        if self.user.u2f_keys.exists():
            ret['u2f'] = KeyResponseForm
        return ret

    def get_user(self):
        try:
            user_id = self.request.session['u2f_pre_verify_user_pk']
            backend_path = self.request.session['u2f_pre_verify_user_backend']
            self.request.session['verfied_u2f'] = False
            assert backend_path in settings.AUTHENTICATION_BACKENDS
            backend = load_backend(backend_path)
            user = backend.get_user(user_id)
            if user is not None:
                user.backend = backend_path
            return user
        except (KeyError, AssertionError):
            return None

    def dispatch(self, request, *args, **kwargs):
        self.user = self.get_user()
        if self.user is None:
            return HttpResponseRedirect(settings.LOGIN_URL)
        return super(VerifySecondFactorView, self).dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        forms = self.get_forms()
        form = forms[request.POST['type']]
        if form.is_valid():
            return self.form_valid(form, forms)
        else:
            return self.form_invalid(forms)

    def form_invalid(self, forms):
        return self.render_to_response(self.get_context_data(
            forms=forms,
        ))

    def get_form_kwargs(self):
        return {
            'user': self.user,
            'request': self.request,
            'appId': self.get_origin(),
        }

    def get_forms(self):
        kwargs = self.get_form_kwargs()
        if self.request.method == 'GET':
            forms = {key: form(**kwargs)
                     for key, form in self.form_classes.items()}
        else:
            method = self.request.POST['type']
            forms = {
                key: form(**kwargs)
                for key, form in self.form_classes.items()
                if key != method
            }
            forms[method] = self.form_classes[method](
                self.request.POST, **kwargs)
        return forms

    def get_context_data(self, **kwargs):
        if 'forms' not in kwargs:
            kwargs['forms'] = self.get_forms()
        kwargs = super(VerifySecondFactorView, self).get_context_data(**kwargs)
        if self.request.GET.get('admin'):
            kwargs['base_template'] = 'admin/base_site.html'
        else:
            kwargs['base_template'] = 'u2f_base.html'
        kwargs['user'] = self.user
        return kwargs

    def form_valid(self, form, forms):
        if not form.validate_second_factor():
            return self.form_invalid(forms)

        del self.request.session['u2f_pre_verify_user_pk']
        del self.request.session['u2f_pre_verify_user_backend']
        self.request.session['verfied_otp'] = True
        self.request.session['verfied_u2f'] = True

        auth.login(self.request, self.user)

        redirect_to = self.request.POST.get(auth.REDIRECT_FIELD_NAME,
                                            self.request.GET.get(auth.REDIRECT_FIELD_NAME, ''))
        if not is_safe_url(url=redirect_to, allowed_hosts=self.request.get_host()):
            redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)
        return HttpResponseRedirect(redirect_to)


class KeyManagementView(ListView):
    template_name = 'u2f/key_list.html'

    def get_queryset(self):
        return self.request.user.u2f_keys.all()

    def post(self, request):
        assert 'delete' in self.request.POST
        key = get_object_or_404(self.get_queryset(),
                                pk=self.request.POST['key_id'])
        key.delete()
        if self.get_queryset().exists():
            messages.success(request, _("Key removed."))
        else:
            messages.success(request, _(
                "Key removed. Two-factor auth disabled."))
        return HttpResponseRedirect(reverse('mfa:u2f_keys'))


add_key = login_required(AddKeyView.as_view())
verify_second_factor_u2f = VerifySecondFactorView.as_view()
keys = login_required(KeyManagementView.as_view())

