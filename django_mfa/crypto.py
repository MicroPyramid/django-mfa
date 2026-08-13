from django.core import signing

from django_mfa.conf import settings as mfa_settings

PREFIX = "mfa1:"


def encrypt(value):
    keys = mfa_settings.MFA_SECRET_ENCRYPTION_KEYS
    if not keys:
        return value
    return PREFIX + signing.dumps(value, key=keys[0], salt="django_mfa.secret",
                                  compress=True)


def decrypt(value):
    if not value.startswith(PREFIX):
        return value  # stored before encryption was enabled
    payload = value[len(PREFIX):]
    keys = mfa_settings.MFA_SECRET_ENCRYPTION_KEYS or []
    for key in keys:
        try:
            return signing.loads(payload, key=key, salt="django_mfa.secret")
        except signing.BadSignature:
            continue
    raise signing.BadSignature("No configured key could decrypt this secret.")
