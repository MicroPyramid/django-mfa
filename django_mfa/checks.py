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


def check_grace_configuration(app_configs, **kwargs):
    """Grace that is configured but cannot possibly work.

    Every case here fails by silently granting NO grace, which is the worst
    failure mode this feature has: the operator believes they shipped a ramp
    and in fact shipped a wall, and they find out from their users. Gated so
    an install with neither setting evaluates nothing.

    MFA_GRACE_ANCHOR is validated the same way MFA_REQUIRED/E004,
    MFA_API_AUTHENTICATION/E006 and MFA_CLIENT_IP_RESOLVER/E009 already are:
    imported here (if it's a string) and asserted callable, rather than left
    to fail at request time. Without this, a typo'd dotted path is not
    caught until policy._anchor() imports and calls it inside
    required_at() -> mfa_required_for() -> MfaMiddleware, i.e. a 500 raised
    from middleware on the first request from any user MFA_REQUIRED matches.

    MFA_GRACE_ANCHOR set without MFA_GRACE_PERIOD is the same failure class
    as MFA_ADMIN_STEPUP without MFA_PROTECT_ADMIN (E011): required_at() only
    ever calls _anchor() when _period() is not None, so the anchor is
    silently never consulted.
    """
    import datetime

    from django.contrib.auth import get_user_model

    errors = []

    cutover = mfa_settings.MFA_REQUIRED_FROM
    if cutover is not None and not isinstance(cutover, datetime.date):
        # datetime is a subclass of date, so this accepts both.
        errors.append(Error(
            f"MFA_REQUIRED_FROM must be a date or datetime, got "
            f"{type(cutover).__name__}.",
            hint="A string is not parsed. Use datetime.date(2026, 9, 1).",
            id="django_mfa.E010",
        ))

    anchor_setting = mfa_settings.MFA_GRACE_ANCHOR
    if anchor_setting is not None:
        anchor = anchor_setting
        if isinstance(anchor, str):
            try:
                anchor = import_string(anchor)
            except ImportError as exc:
                errors.append(Error(
                    f"MFA_GRACE_ANCHOR is not importable: {exc}",
                    hint="Set it to a dotted path to a callable taking a "
                         "user and returning a datetime or None, or leave "
                         "it unset to use user.date_joined.",
                    id="django_mfa.E010",
                ))
                anchor = None
        if anchor is not None and not callable(anchor):
            errors.append(Error(
                f"MFA_GRACE_ANCHOR must be a callable, or a dotted path to "
                f"one -- got {anchor_setting!r}.",
                hint="It takes a user and returns the datetime their "
                     "personal grace window starts from, or None to fall "
                     "back to MFA_REQUIRED_FROM alone.",
                id="django_mfa.E010",
            ))
        if mfa_settings.MFA_GRACE_PERIOD is None:
            errors.append(Error(
                "MFA_GRACE_ANCHOR is set but MFA_GRACE_PERIOD is not.",
                hint="Nothing reads MFA_GRACE_ANCHOR unless MFA_GRACE_PERIOD "
                     "is also set -- required_at() only consults the anchor "
                     "for a per-user window, and there is none without a "
                     "period. Set MFA_GRACE_PERIOD.",
                id="django_mfa.E010",
            ))

    period = mfa_settings.MFA_GRACE_PERIOD
    if period is not None:
        if isinstance(period, datetime.timedelta):
            negative = period < datetime.timedelta(0)
        else:
            try:
                negative = period < 0
            except TypeError:
                # A non-numeric, non-timedelta value (e.g. "14" instead of
                # 14) would otherwise raise a bare TypeError out of this
                # check instead of being reported like every other bad
                # setting here. Nothing left to check against an unusable
                # value, so skip the negative/anchor checks below.
                errors.append(Error(
                    f"MFA_GRACE_PERIOD must be a number of days, a "
                    f"datetime.timedelta, or None, got {period!r}.",
                    hint="Use an int or float number of days, a "
                         "datetime.timedelta, or None to switch the "
                         "per-user window off.",
                    id="django_mfa.E010",
                ))
                negative = False
                period = None
        if negative:
            errors.append(Error(
                "MFA_GRACE_PERIOD is negative.",
                hint="A negative window is already expired for every user, "
                     "which grants no grace at all. Use a positive number of "
                     "days, or None to switch the per-user window off.",
                id="django_mfa.E010",
            ))
        elif period is not None and (
                mfa_settings.MFA_GRACE_ANCHOR is None
                and not hasattr(get_user_model(), "date_joined")):
            errors.append(Error(
                "MFA_GRACE_PERIOD is set but AUTH_USER_MODEL has no "
                "date_joined field and MFA_GRACE_ANCHOR is unset.",
                hint="The per-user window has no clock to start from, so no "
                     "user will receive one. Set MFA_GRACE_ANCHOR to a "
                     "callable (or dotted path) returning the datetime each "
                     "user's window starts from.",
                id="django_mfa.E010",
            ))

    return errors


def check_admin_stepup(app_configs, **kwargs):
    """MFA_ADMIN_STEPUP without MFA_PROTECT_ADMIN does nothing at all.

    Nothing reads MFA_ADMIN_STEPUP unless the admin site has been wrapped,
    and only MFA_PROTECT_ADMIN wraps it. An operator setting the stronger
    of the two alone believes the admin is step-up protected and it is not
    protected at all.
    """
    if mfa_settings.MFA_ADMIN_STEPUP and not mfa_settings.MFA_PROTECT_ADMIN:
        return [Error(
            "MFA_ADMIN_STEPUP is set but MFA_PROTECT_ADMIN is not.",
            hint="Nothing reads MFA_ADMIN_STEPUP unless MFA_PROTECT_ADMIN "
                 "has wrapped the admin site, so the admin is currently "
                 "unprotected. Set MFA_PROTECT_ADMIN = True.",
            id="django_mfa.E011",
        )]
    return []
