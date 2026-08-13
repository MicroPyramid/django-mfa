
from django.apps import AppConfig
from django.core.checks import register


class DjangoMfaAppConfig(AppConfig):
    name = 'django_mfa'
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from django_mfa.checks import (
            check_fido2_rp_id,
            check_webauthn_backend_configured,
        )

        register(check_fido2_rp_id)
        register(check_webauthn_backend_configured)

        from django_mfa import (
            adapters,  # noqa: F401  (registers built-ins)
            signals,  # noqa: F401
        )
