from django_mfa.views import *
from django.urls import path, include
from django.conf import settings


app_name = "mfa"

security_patterns = [
    path("security/", security_settings, name="security_settings"),
    path("mfa/configure/", configure_mfa, name="configure_mfa"),
    path("mfa/enable/", enable_mfa, name="enable_mfa"),
    path("verify/token/", verify_otp, name="verify_otp"),
    path("recovery/codes/", recovery_codes, name="recovery_codes"),
    path(
        "recovery/codes/downloads/",
        recovery_codes_download,
        name="recovery_codes_download",
    ),
]

if not settings.ENFORCE_MFA:
    security_patterns += (path("mfa/disable/", disable_mfa, name="disable_mfa"),)

urlpatterns = [
    path("", include(security_patterns)),
]
