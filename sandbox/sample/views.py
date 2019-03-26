from django.shortcuts import render
from django.contrib.auth import login, logout
from django.http.response import HttpResponseRedirect, JsonResponse
from .forms import RegistrationForm, LoginForm
from django.contrib.auth.models import User
from django_mfa.models import is_u2f_enabled


def index(request):
    if request.user and request.user.is_authenticated:
        return HttpResponseRedirect('/home/')
    if request.method == 'POST':
        form = LoginForm(request.POST, request.FILES)
        if form.is_valid():
            user = form.user
            if is_u2f_enabled(user):
                request.session['u2f_pre_verify_user_pk'] = user.pk
                request.session['u2f_pre_verify_user_backend'] = user.backend
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
