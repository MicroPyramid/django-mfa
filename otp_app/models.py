from django.db import models
from django.conf import settings


class UserOTP(models.Model):

    OTP_TYPES = (
                ('HOTP', 'hotp'),
                ('TOTP', 'totp'),
    )

    user = models.OneToOneField(settings.AUTH_USER_MODEL)
    otp_type = models.CharField(max_length=20, choices=OTP_TYPES)
    secret_key = models.CharField(max_length=100, blank=True)


def is_mfa_enabled(user):
    try:
        user_otp = user.userotp
        return True
    except:
        return False
