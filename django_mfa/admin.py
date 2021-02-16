from django.contrib import admin
from .models import *

admin.site.register(UserOTP)
admin.site.register(UserRecoveryCodes)
