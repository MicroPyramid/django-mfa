from django.conf import settings
from django.db import models


class UserOTP(models.Model):

    OTP_TYPES = (
        ('HOTP', 'hotp'),
        ('TOTP', 'totp'),
    )

    user = models.OneToOneField(settings.AUTH_USER_MODEL)
    otp_type = models.CharField(max_length=20, choices=OTP_TYPES)
    secret_key = models.CharField(max_length=100, blank=True)


def is_mfa_enabled(user):
    """
    Determine if a user has MFA enabled
    """
    return hasattr(user, 'userotp')
