from django.conf.urls import include, url
from .views import *

security_patterns = ([
    url(r'^security/$', security_settings, name="security_settings"),
    url(r'^mfa/configure/$', configure_mfa, name="configure_mfa"),
    url(r'^mfa/enable/$', enable_mfa, name="enable_mfa"),
    url(r'^verify/token/$', verify_otp, name="verify_otp"),
    url(r'^mfa/disable/$', disable_mfa, name="disable_mfa"),
    url(r'^recovery-codes/',recovery_codes,name="recovery_codes"),
    url(r'^recovery-codes-downloads/',recovery_codes_download,name="recovery_codes_download"),
], 'mfa')

urlpatterns = [
    url(r'', include(security_patterns)),
]
