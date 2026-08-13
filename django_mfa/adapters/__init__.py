# django_mfa/adapters/__init__.py
#
# Importing this package registers the built-in MFA factor adapters with
# django_mfa.registry.registry. It is imported from DjangoMfaAppConfig.ready()
# so that registration happens once, at app startup, before any view or
# management command asks the registry for adapters.
#
# Which of the built-ins actually get registered is controlled by
# MFA_FACTORS (django_mfa.conf.DEFAULTS), default
# ["totp", "recovery_codes", "webauthn"] -- i.e. every install behaves
# exactly as before unless a host project opts out of one. This exists so a
# TOTP-only project can set MFA_FACTORS = ["totp", "recovery_codes"] and
# never register a WebAuthn adapter at all, which in turn is what lets
# django_mfa.checks (E001/E002/E003) skip its WebAuthn-only requirements
# (MFA_FIDO2_RP_ID, WebAuthnBackend) for that project -- see checks.py's
# _webauthn_active().
from django.core.exceptions import ImproperlyConfigured

from django_mfa.conf import settings as mfa_settings
from django_mfa.registry import registry

from .email import EmailAdapter
from .recovery_codes import RecoveryCodesAdapter
from .totp import TOTPAdapter
from .webauthn import WebAuthnAdapter

#: Every built-in adapter class, keyed by the same type string MFA_FACTORS
#: names it with. A later task adding a new built-in factor adds it here.
BUILTIN_ADAPTERS = {
    "totp": TOTPAdapter,
    "recovery_codes": RecoveryCodesAdapter,
    "webauthn": WebAuthnAdapter,
    "email": EmailAdapter,
}


def register_default_adapters(target_registry, factor_types):
    """Register the built-ins named in ``factor_types`` (in order) into
    ``target_registry``.

    Split out from the module-level call below so tests can exercise "what
    does a given MFA_FACTORS list register" directly, against a throwaway
    Registry() -- the production registry is populated exactly once, at app
    startup, from whatever MFA_FACTORS was set to at that time (see
    DjangoMfaAppConfig.ready()), so overriding the setting in a test after
    startup has no effect on it.
    """
    for factor_type in factor_types:
        try:
            adapter_class = BUILTIN_ADAPTERS[factor_type]
        except KeyError:
            # A typo here would otherwise surface as a bare KeyError out of
            # AppConfig.ready(), naming neither the setting nor the valid
            # values.
            raise ImproperlyConfigured(
                f"MFA_FACTORS contains unknown factor {factor_type!r}. "
                f"Valid values are: {', '.join(sorted(BUILTIN_ADAPTERS))}."
            ) from None
        target_registry.register(adapter_class())


register_default_adapters(registry, mfa_settings.MFA_FACTORS)
