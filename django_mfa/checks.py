from django.conf import settings as django_settings
from django.core.checks import Error
from django.utils.module_loading import import_string

from django_mfa.conf import settings as mfa_settings


def _webauthn_active():
    """Whether this install has WebAuthn switched on at all.

    The single predicate every WebAuthn-only system check (E001, E002, E003
    below) is gated on. True when either:

    - a WebAuthn-type adapter is registered (the default -- see
      django_mfa.adapters.BUILTIN_ADAPTERS/MFA_FACTORS -- but a host project
      that sets ``MFA_FACTORS = ["totp", "recovery_codes"]`` never registers
      one), or
    - ``MFA_QUICKLOGIN`` is on: passwordless login (``mfa:passkey_begin``/
      ``mfa:passkey_complete``) is exposed by ``django_mfa.urls``
      unconditionally and always builds a ``Fido2Server`` bound to
      ``MFA_FIDO2_RP_ID`` (see ``get_server()`` in
      ``adapters/webauthn.py``) regardless of whether a "webauthn"-type
      adapter is registered for enrollment/verification, so this needs its
      own settings even with the adapter switched off.

    A project where neither is true (TOTP-only, no quicklogin) has no code
    path that ever touches WebAuthn settings or WebAuthnBackend, so none of
    E001/E002/E003 have anything to check.
    """
    from django_mfa.models import Authenticator
    from django_mfa.registry import registry

    webauthn_registered = any(
        adapter.type == Authenticator.Type.WEBAUTHN for adapter in registry.all())
    return mfa_settings.MFA_QUICKLOGIN or webauthn_registered


def check_fido2_rp_id(app_configs, **kwargs):
    if not _webauthn_active():
        return []

    rp_id = mfa_settings.MFA_FIDO2_RP_ID
    if not rp_id:
        return [Error(
            "MFA_FIDO2_RP_ID is not set.",
            hint="WebAuthn credentials are bound to the RP ID. Set it to your "
                 "registrable domain, e.g. 'example.com'. It cannot be changed "
                 "later without invalidating every registered credential.",
            id="django_mfa.E001",
        )]

    hosts = [h for h in django_settings.ALLOWED_HOSTS if h not in ("*", "")]
    if hosts and not any(h == rp_id or h.endswith("." + rp_id) for h in hosts):
        return [Error(
            f"MFA_FIDO2_RP_ID {rp_id!r} is not a suffix of any ALLOWED_HOSTS entry.",
            hint="Credentials will fail to resolve. The RP ID must equal or be a "
                 "parent domain of the host serving the ceremony.",
            id="django_mfa.E002",
        )]
    return []


def check_webauthn_backend_configured(app_configs, **kwargs):
    """``django_mfa.backends.WebAuthnBackend`` must be in
    ``AUTHENTICATION_BACKENDS`` whenever passwordless (passkey) login is
    reachable.

    ``django_mfa.urls`` always exposes ``mfa:passkey_begin``/
    ``mfa:passkey_complete`` -- no setting gates the URLs themselves off.
    ``passkey_complete()`` (django_mfa/views/verify.py) calls
    ``auth.login(request, user, backend=BACKEND_PATH)`` with this backend's
    dotted path passed explicitly, which *succeeds* regardless of
    ``AUTHENTICATION_BACKENDS``: ``django.contrib.auth.login()`` only
    consults that setting when ``backend`` is omitted, never to validate one
    that was passed in. The failure surfaces one request later instead:
    ``django.contrib.auth.get_user()``, called by ``AuthenticationMiddleware``
    on every subsequent request, DOES check the stored backend path against
    ``AUTHENTICATION_BACKENDS`` and silently returns ``AnonymousUser`` if
    it's missing -- no exception, no log line. A user who just
    "successfully" signed in with a passkey is anonymous again on their very
    next click, and stays that way (the stale, still-authenticated-looking
    session key is never cleared) until they explicitly log out.

    Raised as an ``Error`` -- like ``check_fido2_rp_id`` above -- rather
    than a ``Warning``: the failure mode is not a style nit, it is a
    completely silent authentication break with no exception or log output
    anywhere in the request/response cycle to reveal it, and ``manage.py
    runserver``/``migrate`` refusing to start is a far cheaper way to learn
    about it than a support ticket from a confused user.

    Gated on ``_webauthn_active()`` above -- either ``MFA_QUICKLOGIN`` (the
    strongest signal a host project is deliberately building a
    passwordless-login UI around this) or a registered WebAuthn-type adapter
    (the underlying capability -- registered by default, but ``MFA_FACTORS``
    or ``registry.unregister("webauthn")`` can turn it off, at which point
    neither passkey URL can resolve a real credential and the check no
    longer applies). Checking only one of the two would miss a host project
    that relies on the other.
    """
    from django_mfa.backends import WebAuthnBackend

    if not _webauthn_active():
        return []

    backend_path = f"{WebAuthnBackend.__module__}.{WebAuthnBackend.__qualname__}"
    if backend_path in django_settings.AUTHENTICATION_BACKENDS:
        return []

    return [Error(
        f"{backend_path} is not in AUTHENTICATION_BACKENDS.",
        hint="Passwordless (passkey) login logs a user in via this backend, "
             "but Django's own get_user() re-checks that backend path "
             "against AUTHENTICATION_BACKENDS on every later request. "
             "Without it, a passkey login appears to succeed and then "
             "silently degrades to an anonymous session on the very next "
             f"request. Add {backend_path!r} to AUTHENTICATION_BACKENDS.",
        id="django_mfa.E003",
    )]


def check_mfa_required_predicate(app_configs, **kwargs):
    """``MFA_REQUIRED`` must be something policy.resolve() can use.

    Deliberately NOT gated on ``_webauthn_active()``. That gate exists so a
    TOTP-only project isn't asked for WebAuthn settings; MFA_REQUIRED is not
    WebAuthn-specific and applies to every install.

    Without this check the failure surfaces as an ImportError or TypeError
    raised from inside MfaMiddleware, on a user's first request after
    deploy, on every request -- i.e. a total outage discovered in production
    rather than a refused `manage.py check`.
    """
    from django.core.exceptions import ImproperlyConfigured

    from django_mfa import policy

    try:
        policy.resolve()
    except (ImportError, ImproperlyConfigured, TypeError) as exc:
        return [Error(
            f"MFA_REQUIRED is not usable: {exc}",
            hint="Set it to False (nobody), True (everyone), a callable "
                 "taking a user and returning a bool, or a dotted path to "
                 "one. django_mfa.policy.is_staff and "
                 "django_mfa.policy.in_groups(...) are supplied.",
            id="django_mfa.E004",
        )]
    return []


def check_stepup_max_age(app_configs, **kwargs):
    """``MFA_STEPUP_MAX_AGE`` must be a positive integer, or None to disable.

    Deliberately NOT gated on ``_webauthn_active()`` -- like E004, this
    applies to every install.

    Zero is refused rather than accepted because it means "always stale":
    every gated view would redirect to mfa:verify, which marks the session
    verified and redirects back, which is stale again the instant any
    measurable time has passed -- a redirect loop rather than a security
    setting. django_mfa.ratelimit.parse() refuses a zero count and a zero
    window for the same class of reason. bool is excluded explicitly because
    it is a subclass of int, so ``True`` would otherwise be accepted as a
    one-second window.
    """
    value = mfa_settings.MFA_STEPUP_MAX_AGE
    if value is None:
        return []
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return [Error(
            f"MFA_STEPUP_MAX_AGE must be a positive integer or None, "
            f"got {value!r}.",
            hint="It is a number of seconds -- 300 is the default. Set it to "
                 "None to switch step-up re-authentication off entirely.",
            id="django_mfa.E005",
        )]
    return []


def check_mfa_api_authentication(app_configs, **kwargs):
    """``MFA_API_AUTHENTICATION`` must be something api.auth.resolve() can use.

    Deliberately NOT gated on ``_webauthn_active()`` -- like E004 and E005,
    this has nothing to do with WebAuthn.

    It IS gated on the setting being set at all, which is the default: a
    project that never mounts the JSON API never sets it and never sees
    this.

    Without the check, a bad dotted path surfaces as an ImportError from
    inside the first API request, which for an API client means an opaque
    500 rather than a refused deploy.
    """
    from django.core.exceptions import ImproperlyConfigured

    from django_mfa.api import auth

    try:
        auth.resolve()
    except (ImportError, ImproperlyConfigured, TypeError) as exc:
        return [Error(
            f"MFA_API_AUTHENTICATION is not usable: {exc}",
            hint="Set it to None (use request.user, i.e. Django's session "
                 "authentication), a callable taking a request and returning "
                 "a user or None, or a dotted path to one.",
            id="django_mfa.E006",
        )]
    return []


def check_rate_limit_specs(app_configs, **kwargs):
    """Every ``<count>/<window><unit>`` setting must parse.

    Deliberately NOT gated on ``_webauthn_active()`` -- like E004-E006, this
    applies to every install.

    Without this the failure is late and badly placed: ratelimit.parse()
    raises from inside the *first verification attempt*, which is a 500 on the
    challenge page for whichever user happens to log in first after the
    deploy. A refused ``manage.py check`` is the same information, hours
    earlier, aimed at whoever wrote the typo.

    MFA_VERIFY_IP_RATE_LIMIT alone accepts None, which switches the per-IP
    budget off -- the escape hatch for a deployment that genuinely cannot
    identify its clients (see ratelimit.client_ip).
    """
    from django_mfa import ratelimit

    errors = []
    specs = [
        ("MFA_VERIFY_RATE_LIMIT", False),
        ("MFA_VERIFY_IP_RATE_LIMIT", True),
        ("MFA_EMAIL_SEND_RATE_LIMIT", False),
    ]
    for name, nullable in specs:
        value = getattr(mfa_settings, name)
        if value is None and nullable:
            continue
        try:
            ratelimit.parse(value, name)
        except (ValueError, TypeError) as exc:
            errors.append(Error(
                f"{name} is not usable: {exc}",
                hint='The format is "<count>/<window><unit>", where unit is '
                     's, m or h -- "5/5m" means five attempts per five '
                     'minutes.' + (
                         " Set it to None to switch this budget off entirely."
                         if nullable else ""),
                id="django_mfa.E007",
            ))
    return errors


def check_rate_limit_backend(app_configs, **kwargs):
    """``MFA_RATE_LIMIT_BACKEND`` must name a backend that exists.

    A typo here is the worst-shaped failure in this module: ratelimit._backend()
    raises ValueError, which flows.attempt_verify does NOT catch (it catches
    only the adapter's own ValueError/TypeError/KeyError, and this is raised
    before the adapter runs), so every verification attempt 500s. Caught at
    startup instead.
    """
    from django_mfa import ratelimit

    value = mfa_settings.MFA_RATE_LIMIT_BACKEND
    if value in ratelimit.BACKENDS:
        return []
    return [Error(
        f"MFA_RATE_LIMIT_BACKEND must be one of "
        f"{', '.join(repr(b) for b in ratelimit.BACKENDS)}, got {value!r}.",
        hint='"database" (the default) keeps counters in a table, so a cache '
             'restart cannot silently hand an attacker a fresh budget. '
             '"cache" is the older behaviour and needs no migration.',
        id="django_mfa.E008",
    )]


def check_client_ip_resolver(app_configs, **kwargs):
    """``MFA_CLIENT_IP_RESOLVER`` must be importable and callable.

    Gated on the setting being set at all, which is not the default: a project
    that never sets it uses REMOTE_ADDR and never sees this.

    Resolved eagerly here rather than on first use because the alternative is
    an ImportError raised from inside a verification attempt -- and unlike a
    bad rate-limit spec, that one fails *during* somebody's login rather than
    during the deploy that caused it.
    """
    value = mfa_settings.MFA_CLIENT_IP_RESOLVER
    if value is None:
        return []
    try:
        resolver = import_string(value) if isinstance(value, str) else value
    except ImportError as exc:
        return [Error(
            f"MFA_CLIENT_IP_RESOLVER is not importable: {exc}",
            hint="Set it to a dotted path to a callable taking a request and "
                 "returning the client's address as a string, or None to use "
                 "REMOTE_ADDR.",
            id="django_mfa.E009",
        )]
    if not callable(resolver):
        return [Error(
            f"MFA_CLIENT_IP_RESOLVER must be a callable, or a dotted path to "
            f"one -- got {value!r}.",
            hint="It takes a request and returns the client's address as a "
                 "string, or None to skip the per-IP budget for that request.",
            id="django_mfa.E009",
        )]
    return []
