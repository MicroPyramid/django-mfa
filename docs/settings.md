# Settings reference

Every setting below lives in `django_mfa.conf.DEFAULTS` and is read through
`django_mfa.conf.settings`, which falls back to the default shown when the host
project hasn't set it. Set them in your project's normal settings module — there
is no separate config object to construct.

django-mfa reads **only** the names listed here. Asking `django_mfa.conf.settings`
for anything else raises `AttributeError` rather than silently returning `None`,
so a typo in a setting name surfaces immediately instead of quietly disabling a
feature.

Nothing here is required to get started except the two marked **required for
WebAuthn** — see {doc}`installation_setup`.

## Core

| Setting | Default | Purpose |
|---|---|---|
| `MFA_FACTORS` | `["totp", "recovery_codes", "webauthn"]` | Which built-in factor adapters get registered at startup. See [Choosing which factors to offer](#choosing-which-factors-to-offer) below. |
| `MFA_ISSUER_NAME` | `None` | Issuer label shown next to the username in the user's authenticator app when enrolling TOTP. Set it to your product name; without it the app shows the username alone, which is confusing for anyone with more than one account. |
| `MFA_EXEMPT_PATHS` | `[]` | URL paths reachable while a session is pending a second factor. **Must include your logout URL** — see the warning below. |

## Appearance

| Setting | Default | Purpose |
|---|---|---|
| `MFA_BASE_TEMPLATE` | `"django_mfa/base.html"` | Template every django-mfa page extends. Pointing this at your own base template is usually all the theming you need — see {doc}`customizing`. |

## Convenience

| Setting | Default | Purpose |
|---|---|---|
| `MFA_REMEMBER_MY_BROWSER` | `False` | When `True`, a signed cookie trusts a browser for `MFA_REMEMBER_DAYS` after it completes one second-factor challenge, skipping the challenge on later logins. |
| `MFA_REMEMBER_DAYS` | `90` | How long a trusted-browser cookie stays valid. Ignored unless the above is on. |
| `MFA_QUICKLOGIN` | `False` | Sets a non-authenticating hint cookie naming the last account to log in on this browser, so your login page can offer a passkey before asking for a username. See {doc}`recipes`. |

## Hardening

| Setting | Default | Purpose |
|---|---|---|
| `MFA_VERIFY_RATE_LIMIT` | `"5/5m"` | Failed second-factor attempts allowed per user per factor type, as `"<count>/<window><unit>"` where unit is `s`, `m`, or `h`. See {doc}`security`. |
| `MFA_SECRET_ENCRYPTION_KEYS` | `None` | List of keys used to encrypt TOTP secrets at rest. The first key encrypts; every key is tried when decrypting. See [Encrypting stored secrets](#encrypting-stored-secrets). |
| `MFA_OWNED_BY_ENTERPRISE` | `False` | When `True`, users cannot remove their own WebAuthn authenticators from the security settings page — e.g. an organization-issued security key an administrator manages instead. |

## WebAuthn (security keys and passkeys)

Only consulted when a WebAuthn adapter is registered. A project that sets
`MFA_FACTORS = ["totp", "recovery_codes"]` can ignore this whole section.

| Setting | Default | Purpose |
|---|---|---|
| `MFA_FIDO2_RP_ID` | `None` | **Required for WebAuthn.** Your registrable domain, e.g. `"example.com"`. See the warning below before setting it. |
| `MFA_FIDO2_RP_NAME` | `"django-mfa"` | Human-readable relying party name shown by some authenticators during registration. Set this to your product name. |
| `MFA_FIDO2_RESIDENT_KEY` | `"preferred"` | The `residentKey` requirement passed to `navigator.credentials.create()`: `"required"`, `"preferred"`, or `"discouraged"`. Must be `"required"` or `"preferred"` for passwordless login, which depends on a discoverable credential. |
| `MFA_FIDO2_USER_VERIFICATION` | `"preferred"` | The `userVerification` requirement: `"required"`, `"preferred"`, or `"discouraged"`. At `"required"`, a passkey login only ever succeeds when it *also* satisfies the second factor — see {doc}`mfa_flow`. |
| `MFA_FIDO2_AUTHENTICATOR_ATTACHMENT` | `None` | Restricts registration to `"platform"` (built-in: Touch ID, Windows Hello) or `"cross-platform"` (roaming: a USB security key). `None` allows either, which is almost always what you want. |
| `MFA_FIDO2_ATTESTATION_PREFERENCE` | `"none"` | The `attestation` conveyance preference: `"none"`, `"indirect"`, or `"direct"`. Leave at `"none"` unless you have a compliance reason to collect attestation statements — `"direct"` makes some browsers show an extra privacy prompt. |

:::{warning}
**`MFA_FIDO2_RP_ID` cannot be changed later without invalidating every registered credential.**
WebAuthn credentials are cryptographically bound to the relying party ID at
registration time; changing it makes every previously registered security key and
passkey unusable, with no way to migrate them — affected users must delete and
re-enroll. Set it once, up front, to your registrable domain (e.g. `"example.com"`),
and treat any later change as equivalent to revoking every WebAuthn credential in
the system. `django_mfa.checks` (`django_mfa.E001` / `django_mfa.E002`) refuses to
start the project at all if this is unset or does not match `ALLOWED_HOSTS` — that
is deliberate: it is far cheaper to catch this before a single credential is ever
registered against the wrong value than after.
:::

## Choosing which factors to offer

`MFA_FACTORS` controls which built-in adapters are registered at app startup
(`django_mfa.adapters.register_builtins`, called from `DjangoMfaAppConfig.ready()`).
The default registers all three, so an existing install behaves the same unless you
set this explicitly.

    # TOTP only: no security keys, no passkeys.
    MFA_FACTORS = ["totp", "recovery_codes"]

Narrowing the list also switches off the WebAuthn-only system checks below, since
no WebAuthn adapter is ever registered and there is nothing for them to validate —
a TOTP-only project needs no `MFA_FIDO2_*` settings and no `WebAuthnBackend`.

An unknown name in this list raises `ImproperlyConfigured` at startup, naming the
valid values, rather than silently registering nothing.

:::{warning}
**Narrowing `MFA_FACTORS` silently de-protects users already enrolled in the factor you removed.**
Whether a user is challenged is decided from the *registered* adapters, so dropping
`"totp"` means a user whose only factor is TOTP now logs in with a password alone —
no error, no warning, and their `Authenticator` row still sitting in the database.
This is deliberate: the alternative is challenging users with a picker offering zero
ways to answer it, which locks them out instead. Treat removing a factor as a
migration — require affected users to enroll in a remaining factor *before* you
narrow the list, not after.
:::

:::{warning}
**Set `MFA_EXEMPT_PATHS` to include your project's logout URL.**
`MfaMiddleware` redirects any authenticated, not-yet-verified request to the
second-factor picker, for every path except the ones it derives automatically (the
picker itself and each registered factor's verify page) plus whatever you list here.
A user who cannot complete their second factor — lost device, no recovery codes left
— and whose logout view isn't exempt has **no way to log out**: every request they
make, including to `/logout/`, bounces back to the picker. django-mfa cannot know
your logout URL on its own; list it explicitly:

    MFA_EXEMPT_PATHS = ["/logout/"]

Paths are matched exactly against `request.path`, so include the full path as
mounted, with its trailing slash.
:::

## System checks

django-mfa registers system checks that run on `manage.py check` — and therefore on
`migrate` and `runserver`, which run checks first — to catch the WebAuthn
misconfigurations above before they can affect a real user.

All three are WebAuthn-only. They return no errors at all unless WebAuthn is
actually switched on for this install, meaning `MFA_QUICKLOGIN` is on or a WebAuthn
adapter is registered (true by default). A project with
`MFA_FACTORS = ["totp", "recovery_codes"]` never trips any of them.

| Check ID | Severity | Condition |
|---|---|---|
| `django_mfa.E001` | Error | WebAuthn is active and `MFA_FIDO2_RP_ID` is unset. |
| `django_mfa.E002` | Error | WebAuthn is active and `MFA_FIDO2_RP_ID` is not a suffix of any `ALLOWED_HOSTS` entry. |
| `django_mfa.E003` | Error | WebAuthn is active and `django_mfa.backends.WebAuthnBackend` is missing from `AUTHENTICATION_BACKENDS`. |

`E003` exists because the failure it prevents is otherwise completely silent.
Passwordless login logs a user in by calling `django.contrib.auth.login()` with an
explicit `backend=` argument, which succeeds regardless of `AUTHENTICATION_BACKENDS`.
The break only shows up one request later, when Django's own `get_user()` re-checks
that backend path against `AUTHENTICATION_BACKENDS` and, finding it absent, silently
resolves `request.user` to `AnonymousUser` — no exception, no log line, just a user
who was "logged in" a moment ago and is now anonymous again. Catching this at startup
is far cheaper than a support ticket.

All three are `Error` rather than `Warning` deliberately: each guards a failure mode
that is otherwise silent in production, not a style nit. If a check fires for a
reason you understand and have already accounted for — say you provision
`MFA_FIDO2_RP_ID` from a source Django's check framework can't see at check time —
the standard Django escape hatch applies:

    SILENCED_SYSTEM_CHECKS = ["django_mfa.E001"]

Prefer fixing the configuration (or narrowing `MFA_FACTORS`) over silencing one of
these. Silencing does not make the failure mode go away, only the warning about it.

## Encrypting stored secrets

By default, TOTP secrets are stored in the database in plaintext. Setting
`MFA_SECRET_ENCRYPTION_KEYS` to a list of one or more keys encrypts every secret
written from that point on, using the first key in the list, while still reading
anything encrypted with an older key still present:

    MFA_SECRET_ENCRYPTION_KEYS = [
        "current-key",     # everything new is encrypted with this one
        "previous-key",    # still readable; drop once nothing uses it
    ]

That list *is* the rotation mechanism: add the new key at the front, redeploy, and
once nothing needs the old key anymore, drop it. There is no separate rotation
command to run.

Two limits worth knowing:

- **Existing plaintext secrets are not retroactively encrypted.** They are read
  unchanged and only encrypted the next time they're written — in practice, when the
  user re-enrolls. Turning this on protects new and re-enrolled secrets, not your
  existing table.
- **Losing every key in the list makes those secrets unreadable**, which locks
  affected users out of TOTP until they re-enroll. Keep the keys wherever you keep
  `SECRET_KEY`, and with the same care.

WebAuthn credentials store no secret — only a public key — so this setting does not
apply to them. Recovery codes are hashed rather than encrypted, which is not
configurable.
