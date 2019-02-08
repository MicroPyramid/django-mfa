"""test_django_mfa URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.urls import path, include
from django.contrib import admin
from sample.views import index, home, log_out, register

urlpatterns = [
    path('admin/', admin.site.urls),
    path('settings/', include('django_mfa.urls')),
    path('', index, name='index'),
    path('register/', register, name='register'),
    path('home/', home, name='home'),
    path('logout/', log_out, name='log_out'),
]
