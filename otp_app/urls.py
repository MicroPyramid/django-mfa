from django.conf.urls import url
from .views import *

urlpatterns = [
    url(r'^security/$', security_settings, name="security_settings"),
    url(r'^mfa/configure/$', configure_mfa, name="configure_mfa"),
    url(r'^mfa/enable/$', enable_mfa, name="enable_mfa"),
    url(r'^verify/token/$', verify_otp, name="verify_otp"),
    url(r'^mfa/disable/$', disable_mfa, name="disable_mfa"),
]
