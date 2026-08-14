
from django.apps import AppConfig
from django.core.checks import register


class DjangoMfaAppConfig(AppConfig):
    name = 'django_mfa'
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from django_mfa.checks import (
            check_admin_stepup,
            check_client_ip_resolver,
            check_fido2_rp_id,
            check_grace_configuration,
            check_mfa_api_authentication,
            check_mfa_required_predicate,
            check_rate_limit_backend,
            check_rate_limit_specs,
            check_stepup_max_age,
            check_webauthn_backend_configured,
        )

        register(check_fido2_rp_id)
        register(check_webauthn_backend_configured)
        register(check_mfa_required_predicate)
        register(check_stepup_max_age)
        register(check_mfa_api_authentication)
        register(check_rate_limit_specs)
        register(check_rate_limit_backend)
        register(check_client_ip_resolver)
        register(check_grace_configuration)
        register(check_admin_stepup)

        from django.apps import apps as django_apps

        from django_mfa import (
            adapters,  # noqa: F401  (registers built-ins)
            notifications,  # noqa: F401  (connects notification receivers)
            signals,  # noqa: F401
        )
        from django_mfa.conf import settings as mfa_settings

        # No-op without django.contrib.admin: a project with no admin that
        # sets MFA_PROTECT_ADMIN is odd but must not crash at startup.
        if (mfa_settings.MFA_PROTECT_ADMIN
                and django_apps.is_installed("django.contrib.admin")):
            from django.contrib import admin

            from django_mfa.admin_site import protect_admin_site

            protect_admin_site(admin.site)
