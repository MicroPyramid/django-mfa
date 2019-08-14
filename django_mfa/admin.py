from django.contrib import admin
from .models import *
# Register your models here.

admin.site.register(UserOTP)
admin.site.register(UserRecoveryCodes)
admin.site.register(U2FKey)
