from .views import *
from django.urls import path, include
from . import views

security_patterns = ([
    path('verify-second-factor-options/',
         verify_second_factor, name='verify_second_factor'),
    path('verify/token/u2f/', views.verify_second_factor_u2f,
         name='verify_second_factor_u2f'),
    path('verify/token/totp/', verify_second_factor_totp,
         name='verify_second_factor_totp'),
    path('keys/', views.keys, name='u2f_keys'),
    path('add-key/', views.add_key, name='add_u2f_key'),
    path('security/', security_settings, name='security_settings'),
    path('mfa/configure/', configure_mfa, name='configure_mfa'),
    path('mfa/enable/', enable_mfa, name='enable_mfa'),
    path('mfa/disable/', disable_mfa, name='disable_mfa'),
    path('recovery/codes/', recovery_codes, name='recovery_codes'),
    path('recovery/codes/downloads/', recovery_codes_download,
         name='recovery_codes_download'),
], 'mfa')

urlpatterns = [
    path("", include(security_patterns)),
]
