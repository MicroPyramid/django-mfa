from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from django.http.response import HttpResponseRedirect


# Create your views here.

def index(request):
    if request.user.is_authenticated():
        return HttpResponseRedirect('/home/')
    if request.method == 'POST':
        email = request.POST.get('username')
        password = request.POST.get('password')
        admin = authenticate(username=email, password=password)
        print (admin)
        if admin is not None:
            login(request, admin)
            return HttpResponseRedirect('/home/')
        return render(request, 'login.html', {'errors': True})
    return render(request, 'login.html')


def home(request):
    return render(request, "home.html")


def log_out(request):
    logout(request)
    return HttpResponseRedirect("/")
