
from django.apps import AppConfig
from django.core.checks import register


class DjangoMfaAppConfig(AppConfig):
    name = 'django_mfa'
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from django_mfa.checks import (
            check_fido2_rp_id,
            check_mfa_required_predicate,
            check_stepup_max_age,
            check_webauthn_backend_configured,
        )

        register(check_fido2_rp_id)
        register(check_webauthn_backend_configured)
        register(check_mfa_required_predicate)
        register(check_stepup_max_age)

        from django_mfa import (
            adapters,  # noqa: F401  (registers built-ins)
            notifications,  # noqa: F401  (connects notification receivers)
            signals,  # noqa: F401
        )
