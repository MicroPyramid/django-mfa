from django.shortcuts import render
from django.contrib.auth import login, logout
from django.http.response import HttpResponseRedirect, JsonResponse
from .forms import RegistrationForm, LoginForm
from django.contrib.auth.models import User
from django.conf import settings


def index(request):
    if request.user and request.user.is_authenticated:
        return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)
    if request.method == 'POST':
        form = LoginForm(request.POST, request.FILES)
        if form.is_valid():
            # django_mfa's own user_logged_in signal receiver
            # (django_mfa.signals.stamp_pending_verification) now marks the
            # session pending a second factor, if the user has one, as soon
            # as login() below fires the signal -- a host project's login
            # view no longer has to know or care whether MFA is enabled for
            # this user, and the old u2f_pre_verify_user_pk/
            # u2f_pre_verify_user_backend session dance (and the U2F-specific
            # is_u2f_enabled() check that gated it) is gone. See
            # docs/upgrading.rst item 6.
            login(request, form.user)
            return JsonResponse({"error": False})
        else:
            return JsonResponse({"error": True, "errors": form.errors})
    context = {
        "registration_form": RegistrationForm,
        "login_form": LoginForm
    }
    return render(request, 'login.html', context)


def register(request):
    form = RegistrationForm(request.POST, request.FILES)
    if form.is_valid():
        email = form.cleaned_data.get('email')
        password = form.cleaned_data.get('password')
        user = User.objects.create(email=email, username=email)
        user.set_password(password)
        user.save()
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        login(request, user)
        return JsonResponse({"error": False})
    else:
        return JsonResponse({"error": True, "errors": form.errors})


def home(request):
    return render(request, "home.html")


def log_out(request):
    logout(request)
    return HttpResponseRedirect("/")
