from django.urls import include, path

from django_mfa.views import enroll, manage, picker, verify

security_patterns = ([
    path("security/", manage.security_settings, name="security_settings"),
    path("manage/", manage.manage_factors, name="manage"),
    path("verify/", picker.verify, name="verify"),
    path("verify/<str:factor_type>/", verify.verify_factor, name="verify_factor"),
    path("enroll/<str:factor_type>/", enroll.enroll_factor, name="enroll_factor"),
    path("recovery/codes/", manage.recovery_codes, name="recovery_codes"),
    path("passkey/begin/", verify.passkey_begin, name="passkey_begin"),
    path("passkey/complete/", verify.passkey_complete, name="passkey_complete"),
], "mfa")

urlpatterns = [path("", include(security_patterns))]
