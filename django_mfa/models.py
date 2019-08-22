from __future__ import division
from django.conf import settings
from django.db import models


class UserOTP(models.Model):

    OTP_TYPES = (
        ('HOTP', 'hotp'),
        ('TOTP', 'totp'),
    )

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    otp_type = models.CharField(max_length=20, choices=OTP_TYPES)
    secret_key = models.CharField(max_length=100, blank=True)


def is_mfa_enabled(user):
    """
    Determine if a user has MFA enabled
    """
    return hasattr(user, 'userotp')


class UserRecoveryCodes(models.Model):
    user = models.ForeignKey(UserOTP,
                             on_delete=models.CASCADE)
    secret_code = models.CharField(max_length=10)


class U2FKey(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='u2f_keys',
                             on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True)

    public_key = models.TextField(unique=True)
    key_handle = models.TextField()
    app_id = models.TextField()

    def to_json(self):
        return {
            'publicKey': self.public_key,
            'keyHandle': self.key_handle,
            'appId': self.app_id,
            'version': 'U2F_V2',
        }


def is_u2f_enabled(user):
    """
    Determine if a user has U2F enabled
    """
    return user.u2f_keys.all().exists()

