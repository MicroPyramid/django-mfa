from django.conf import settings as django_settings

DEFAULTS = {
    "MFA_ISSUER_NAME": None,
    "MFA_REMEMBER_MY_BROWSER": False,
    "MFA_REMEMBER_DAYS": 90,
    "MFA_BASE_TEMPLATE": "django_mfa/base.html",
    "MFA_SECRET_ENCRYPTION_KEYS": None,
    "MFA_VERIFY_RATE_LIMIT": "5/5m",
    "MFA_VERIFY_IP_RATE_LIMIT": "50/5m",
    "MFA_RATE_LIMIT_BACKEND": "database",
    "MFA_RATE_LIMIT_FAIL_OPEN": True,
    "MFA_CLIENT_IP_RESOLVER": None,
    "MFA_EMAIL_SEND_RATE_LIMIT": "3/5m",
    "MFA_QUICKLOGIN": False,
    "MFA_OWNED_BY_ENTERPRISE": False,
    "MFA_FACTORS": ["totp", "recovery_codes", "webauthn"],
    "MFA_REQUIRED": False,
    "MFA_REQUIRED_FROM": None,
    "MFA_GRACE_PERIOD": None,
    "MFA_GRACE_ANCHOR": None,
    "MFA_FIDO2_RP_ID": None,
    "MFA_FIDO2_RP_NAME": "django-mfa",
    "MFA_FIDO2_RESIDENT_KEY": "preferred",
    "MFA_FIDO2_AUTHENTICATOR_ATTACHMENT": None,
    "MFA_FIDO2_USER_VERIFICATION": "preferred",
    "MFA_FIDO2_ATTESTATION_PREFERENCE": "none",
    "MFA_EXEMPT_PATHS": [],
    "MFA_STEPUP_MAX_AGE": 300,
    "MFA_EMAIL_CODE_LENGTH": 6,
    "MFA_EMAIL_CODE_VALIDITY": 300,
    "MFA_EMAIL_SUBJECT": None,
    "MFA_FROM_EMAIL": None,
    "MFA_NOTIFY_ON_CHANGE": False,
    "MFA_API_AUTHENTICATION": None,
    "MFA_PROTECT_ADMIN": False,
    "MFA_ADMIN_STEPUP": False,
}


class Settings:
    def __getattr__(self, name):
        if name not in DEFAULTS:
            raise AttributeError(f"{name} is not a django-mfa setting")
        return getattr(django_settings, name, DEFAULTS[name])


settings = Settings()
