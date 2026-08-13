from django.conf import settings as django_settings

DEFAULTS = {
    "MFA_ISSUER_NAME": None,
    "MFA_REMEMBER_MY_BROWSER": False,
    "MFA_REMEMBER_DAYS": 90,
    "MFA_BASE_TEMPLATE": "django_mfa/base.html",
    "MFA_SECRET_ENCRYPTION_KEYS": None,
    "MFA_VERIFY_RATE_LIMIT": "5/5m",
    "MFA_QUICKLOGIN": False,
    "MFA_OWNED_BY_ENTERPRISE": False,
    "MFA_FACTORS": ["totp", "recovery_codes", "webauthn"],
    "MFA_FIDO2_RP_ID": None,
    "MFA_FIDO2_RP_NAME": "django-mfa",
    "MFA_FIDO2_RESIDENT_KEY": "preferred",
    "MFA_FIDO2_AUTHENTICATOR_ATTACHMENT": None,
    "MFA_FIDO2_USER_VERIFICATION": "preferred",
    "MFA_FIDO2_ATTESTATION_PREFERENCE": "none",
    "MFA_EXEMPT_PATHS": [],
}


class Settings:
    def __getattr__(self, name):
        if name not in DEFAULTS:
            raise AttributeError(f"{name} is not a django-mfa setting")
        return getattr(django_settings, name, DEFAULTS[name])


settings = Settings()
