from django.test import TestCase, override_settings

from django_mfa.checks import (
    check_client_ip_resolver,
    check_fido2_rp_id,
    check_rate_limit_backend,
    check_rate_limit_specs,
    check_webauthn_backend_configured,
)
from django_mfa.conf import settings as mfa_settings


class ConfTests(TestCase):
    def test_default_is_returned_when_unset(self):
        self.assertEqual(mfa_settings.MFA_VERIFY_RATE_LIMIT, "5/5m")

    def test_mfa_factors_default_registers_every_builtin(self):
        self.assertEqual(
            mfa_settings.MFA_FACTORS, ["totp", "recovery_codes", "webauthn"])

    @override_settings(MFA_ISSUER_NAME="Cool App")
    def test_project_setting_wins(self):
        self.assertEqual(mfa_settings.MFA_ISSUER_NAME, "Cool App")

    def test_unknown_setting_raises(self):
        with self.assertRaises(AttributeError):
            # The bare attribute access IS the assertion -- evaluating it is
            # what must raise. Binding it to a name would not change that.
            mfa_settings.MFA_NOT_A_REAL_SETTING  # noqa: B018


class ChecksTests(TestCase):
    @override_settings(MFA_FIDO2_RP_ID=None)
    def test_missing_rp_id_is_an_error(self):
        errors = check_fido2_rp_id(app_configs=None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E001"])

    @override_settings(MFA_FIDO2_RP_ID="example.com",
                       ALLOWED_HOSTS=["app.example.com"])
    def test_rp_id_suffix_of_allowed_host_is_ok(self):
        self.assertEqual(check_fido2_rp_id(app_configs=None), [])

    @override_settings(MFA_FIDO2_RP_ID="evil.com",
                       ALLOWED_HOSTS=["app.example.com"])
    def test_rp_id_unrelated_to_allowed_hosts_is_an_error(self):
        errors = check_fido2_rp_id(app_configs=None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E002"])

    def _unregister_webauthn(self):
        from django_mfa.adapters.webauthn import WebAuthnAdapter
        from django_mfa.registry import registry

        registry.unregister("webauthn")
        self.addCleanup(registry.register, WebAuthnAdapter())

    @override_settings(MFA_FIDO2_RP_ID=None, MFA_QUICKLOGIN=False)
    def test_missing_rp_id_is_fine_once_webauthn_is_fully_disabled(self):
        """Finding 4 (final whole-branch review): E001/E002 must be gated on
        WebAuthn actually being active -- exactly like E003 already was --
        or a TOTP-only project (MFA_FACTORS = ["totp", "recovery_codes"])
        can never start `manage.py check`/`runserver`/`migrate` even though
        it never touches WebAuthn at all. Simulating that project here by
        unregistering the adapter the same way MFA_FACTORS would have left
        it unregistered from app startup.
        """
        self._unregister_webauthn()
        self.assertEqual(check_fido2_rp_id(app_configs=None), [])


class MfaFactorsAdapterRegistrationTests(TestCase):
    """MFA_FACTORS controls which built-in adapters get registered --
    django_mfa.adapters.register_default_adapters() is what production code
    calls once, at app startup, with the real registry and whatever
    MFA_FACTORS was set to then. Exercised here against a throwaway
    Registry() instead, since overriding the setting after startup has no
    effect on the already-populated production registry.
    """

    def test_unknown_factor_name_raises_a_setting_naming_error(self):
        """A typo in MFA_FACTORS surfaces during AppConfig.ready(), i.e.
        before anything else in the project starts. A bare KeyError there
        names neither the setting at fault nor the valid values.
        """
        from django.core.exceptions import ImproperlyConfigured

        from django_mfa.adapters import register_default_adapters
        from django_mfa.registry import Registry

        with self.assertRaises(ImproperlyConfigured) as ctx:
            register_default_adapters(Registry(), ["totp", "typoo"])
        message = str(ctx.exception)
        self.assertIn("MFA_FACTORS", message)
        self.assertIn("typoo", message)
        self.assertIn("webauthn", message)  # lists the valid values

    def test_empty_factor_list_registers_nothing(self):
        from django_mfa.adapters import register_default_adapters
        from django_mfa.registry import Registry

        test_registry = Registry()
        register_default_adapters(test_registry, [])
        self.assertEqual(test_registry.all(), [])

    def test_default_factor_list_registers_all_three_builtins(self):
        from django_mfa.adapters import register_default_adapters
        from django_mfa.registry import Registry

        test_registry = Registry()
        register_default_adapters(test_registry, mfa_settings.MFA_FACTORS)
        self.assertEqual(
            {a.type for a in test_registry.all()},
            {"totp", "recovery_codes", "webauthn"})

    def test_totp_only_factor_list_never_registers_webauthn(self):
        from django_mfa.adapters import register_default_adapters
        from django_mfa.registry import Registry

        test_registry = Registry()
        register_default_adapters(test_registry, ["totp", "recovery_codes"])
        self.assertEqual(
            {a.type for a in test_registry.all()}, {"totp", "recovery_codes"})
        with self.assertRaises(KeyError):
            test_registry.get("webauthn")


class WebAuthnBackendCheckTests(TestCase):
    """check_webauthn_backend_configured (django_mfa.E003) -- see the
    function's own docstring in checks.py for why this has to be an Error,
    not a Warning: the failure it catches (a passkey login that "succeeds"
    once and then silently degrades every later request to an anonymous
    session) produces no exception and no log line anywhere on its own.
    """

    BACKENDS_WITH_WEBAUTHN = [
        "django_mfa.backends.WebAuthnBackend",
        "django.contrib.auth.backends.ModelBackend",
    ]
    BACKENDS_WITHOUT_WEBAUTHN = ["django.contrib.auth.backends.ModelBackend"]

    def _unregister_webauthn(self):
        """Temporarily remove the WebAuthn adapter from the real, global
        registry -- the check reads that singleton directly, so exercising
        its "no WebAuthn adapter registered" branch means mutating it, not
        a local Registry() instance the way test_registry.py does. Restored
        via addCleanup (runs even on failure) so no other test ever
        observes a registry missing its WebAuthn adapter.
        """
        from django_mfa.adapters.webauthn import WebAuthnAdapter
        from django_mfa.registry import registry

        registry.unregister("webauthn")
        self.addCleanup(registry.register, WebAuthnAdapter())

    @override_settings(AUTHENTICATION_BACKENDS=BACKENDS_WITH_WEBAUTHN)
    def test_backend_present_is_ok(self):
        # The registry registers a WebAuthn adapter by default, which alone
        # is enough to trigger the check -- this confirms the happy path
        # under that default trigger.
        self.assertEqual(check_webauthn_backend_configured(app_configs=None), [])

    @override_settings(AUTHENTICATION_BACKENDS=BACKENDS_WITHOUT_WEBAUTHN)
    def test_backend_missing_with_webauthn_registered_is_an_error(self):
        errors = check_webauthn_backend_configured(app_configs=None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E003"])

    @override_settings(AUTHENTICATION_BACKENDS=BACKENDS_WITHOUT_WEBAUTHN,
                       MFA_QUICKLOGIN=True)
    def test_backend_missing_with_quicklogin_is_an_error_even_without_the_adapter(self):
        self._unregister_webauthn()
        errors = check_webauthn_backend_configured(app_configs=None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E003"])

    @override_settings(AUTHENTICATION_BACKENDS=BACKENDS_WITHOUT_WEBAUTHN,
                       MFA_QUICKLOGIN=False)
    def test_backend_missing_is_fine_once_webauthn_is_fully_disabled(self):
        self._unregister_webauthn()
        self.assertEqual(check_webauthn_backend_configured(app_configs=None), [])


class RateLimitCheckTests(TestCase):
    """E007-E009. The failure each prevents lands inside a verification
    attempt -- i.e. as a 500 on the challenge page for whichever user logs in
    first after the deploy -- so catching them at `manage.py check` is most of
    their value."""

    def test_the_defaults_are_clean(self):
        self.assertEqual(check_rate_limit_specs(app_configs=None), [])
        self.assertEqual(check_rate_limit_backend(app_configs=None), [])
        self.assertEqual(check_client_ip_resolver(app_configs=None), [])

    @override_settings(MFA_VERIFY_RATE_LIMIT="5 per 5 minutes")
    def test_a_malformed_verify_spec_is_an_error(self):
        errors = check_rate_limit_specs(app_configs=None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E007"])
        self.assertIn("MFA_VERIFY_RATE_LIMIT", errors[0].msg)

    @override_settings(MFA_VERIFY_IP_RATE_LIMIT="0/5m")
    def test_a_zero_count_is_an_error(self):
        errors = check_rate_limit_specs(app_configs=None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E007"])

    @override_settings(MFA_VERIFY_IP_RATE_LIMIT=None)
    def test_the_ip_budget_may_be_switched_off(self):
        self.assertEqual(check_rate_limit_specs(app_configs=None), [])

    @override_settings(MFA_VERIFY_RATE_LIMIT=None)
    def test_the_per_user_budget_may_not_be(self):
        """Only the IP budget is nullable. Allowing None here would silently
        remove the throttle every other guarantee in this package assumes."""
        errors = check_rate_limit_specs(app_configs=None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E007"])

    @override_settings(MFA_VERIFY_RATE_LIMIT="nope", MFA_EMAIL_SEND_RATE_LIMIT="x")
    def test_every_bad_spec_is_reported_not_just_the_first(self):
        errors = check_rate_limit_specs(app_configs=None)
        self.assertEqual(len(errors), 2)
        self.assertEqual({e.id for e in errors}, {"django_mfa.E007"})

    @override_settings(MFA_RATE_LIMIT_BACKEND="postgres")
    def test_an_unknown_backend_is_an_error(self):
        errors = check_rate_limit_backend(app_configs=None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E008"])

    @override_settings(MFA_RATE_LIMIT_BACKEND="cache")
    def test_the_other_real_backend_is_accepted(self):
        self.assertEqual(check_rate_limit_backend(app_configs=None), [])

    @override_settings(MFA_CLIENT_IP_RESOLVER="myapp.nope.missing")
    def test_an_unimportable_resolver_is_an_error(self):
        errors = check_client_ip_resolver(app_configs=None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E009"])

    @override_settings(MFA_CLIENT_IP_RESOLVER="django_mfa.conf.DEFAULTS")
    def test_a_non_callable_resolver_is_an_error(self):
        errors = check_client_ip_resolver(app_configs=None)
        self.assertEqual([e.id for e in errors], ["django_mfa.E009"])

    @override_settings(
        MFA_CLIENT_IP_RESOLVER="django_mfa.tests.test_ratelimit.last_forwarded")
    def test_a_good_resolver_passes(self):
        self.assertEqual(check_client_ip_resolver(app_configs=None), [])
