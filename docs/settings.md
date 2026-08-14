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
| `MFA_REQUIRED` | `False` | Who must hold a second factor. `False` (nobody), `True` (every authenticated user), a callable taking a user and returning a bool, or a dotted path to one. A required user with no factor is walled to the security page until they enroll — see {doc}`enforcement`. |
| `MFA_ISSUER_NAME` | `None` | Issuer label shown next to the username in the user's authenticator app when enrolling TOTP. Set it to your product name; without it the app shows the username alone, which is confusing for anyone with more than one account. |
| `MFA_EXEMPT_PATHS` | `[]` | URL paths reachable through either of `MfaMiddleware`'s walls: a session pending a second factor, and — when `MFA_REQUIRED` applies — a required user who hasn't enrolled one yet. **Must include your logout URL** — see the warning below. |

## Appearance

| Setting | Default | Purpose |
|---|---|---|
| `MFA_BASE_TEMPLATE` | `"django_mfa/base.html"` | Template every django-mfa page extends. Pointing this at your own base template is usually all the theming you need — see {doc}`customizing`. |

## Convenience

| Setting | Default | Purpose |
|---|---|---|
| `MFA_REMEMBER_MY_BROWSER` | `False` | When `True`, a signed cookie trusts a browser for `MFA_REMEMBER_DAYS` after it completes one second-factor challenge, skipping the challenge on later logins. Works with any factor type. The cookie is bound to the user's enrolled factors, so enrolling or removing one invalidates every previously trusted browser. Interacts with step-up (`MFA_STEPUP_MAX_AGE`) — see the note below. |
| `MFA_REMEMBER_DAYS` | `90` | How long a trusted-browser cookie stays valid. Ignored unless the above is on. |
| `MFA_QUICKLOGIN` | `False` | Sets a non-authenticating hint cookie naming the last account to log in on this browser, so your login page can offer a passkey before asking for a username. See {doc}`recipes`. |

## Hardening

| Setting | Default | Purpose |
|---|---|---|
| `MFA_VERIFY_RATE_LIMIT` | `"5/5m"` | Failed second-factor attempts allowed per user per factor type, as `"<count>/<window><unit>"` where unit is `s`, `m`, or `h`. See {doc}`security`. |
| `MFA_VERIFY_IP_RATE_LIMIT` | `"50/5m"` | Failed second-factor attempts allowed per client IP per factor type, across every account. Same grammar; `None` switches it off. See [below](#per-ip-rate-limiting). |
| `MFA_RATE_LIMIT_BACKEND` | `"database"` | Where the counters live: `"database"` (a table, survives a cache restart) or `"cache"`. See [below](#mfa_rate_limit_backend). |
| `MFA_RATE_LIMIT_FAIL_OPEN` | `True` | What to do when the counter store is *unreachable* — allow the attempt (`True`) or refuse it (`False`). Not consulted for a counter that is merely absent, which always means "no failures yet". |
| `MFA_CLIENT_IP_RESOLVER` | `None` | How to find the client's address for the per-IP budget. `None` means `REMOTE_ADDR`. **Set this if you run behind a proxy** — see [below](#per-ip-rate-limiting). |
| `MFA_EMAIL_SEND_RATE_LIMIT` | `"3/5m"` | How many emailed codes a user can be sent per window, same `"<count>/<window><unit>"` grammar as above. Refreshing a challenge page reuses a still-valid code rather than spending budget; past the limit no mail is sent and the page looks exactly the same. Only consulted when `"email"` is in `MFA_FACTORS`. |
| `MFA_SECRET_ENCRYPTION_KEYS` | `None` | **Deprecated, and does not encrypt.** List of keys used to *sign* TOTP secrets at rest. The first key signs; every key is tried when reading. See [Signing stored secrets](#signing-stored-secrets-deprecated). |
| `MFA_OWNED_BY_ENTERPRISE` | `False` | When `True`, users cannot remove their own WebAuthn authenticators from the security settings page — e.g. an organization-issued security key an administrator manages instead. |
| `MFA_NOTIFY_ON_CHANGE` | `False` | When `True`, emails the user when a factor is added or removed, when a recovery code is spent, and when their last factor goes. Off by default so an upgrade doesn't start sending mail unannounced. The `django_mfa.events` signals fire either way — connect your own receiver for async delivery or for routing somewhere other than email. Sending is synchronous and best-effort: a failure is logged, never raised. |
| `MFA_STEPUP_MAX_AGE` | `300` (seconds) | How recently a session must have completed a factor challenge before it may add, remove or regenerate a factor. See [below](#mfa_stepup_max_age). |

### `MFA_STEPUP_MAX_AGE`

Default: `300` (seconds).

How recently a session must have completed a factor challenge before it may
add, remove or regenerate a factor. A session older than this is redirected
back through `mfa:verify` first. Set to `None` to switch the gate off for
django-mfa's own three built-in views (`enroll_factor` and the two
`manage_factors` views) and restore pre-4.2.0 behaviour there — they never
pass their own `max_age`, so they fall back to this setting.

**This does not disable a host view's own explicit `max_age`.**
`@mfa_recent_required(max_age=60)` (or `mfa_stepup_max_age = 60` on
`MfaRecentRequiredMixin`) keeps enforcing 60 seconds regardless of what this
setting is — `decorators._enforce_recent` resolves `max_age if max_age is
not None else MFA_STEPUP_MAX_AGE`, so an explicit per-view value always
outranks the global one. Setting this to `None` is a *default*, not a
ceiling: it switches off step-up for views that don't ask for their own
freshness window, not for ones that do.

**Interacts with `MFA_REMEMBER_MY_BROWSER`.** A trusted browser still skips
the *login* challenge exactly as before, but the session it starts is only
fresh at the moment it's created — `MFA_STEPUP_MAX_AGE` (or a view's own
`max_age`) is enforced on every factor change regardless of how the session
became verified. A trusted browser that changes a factor more than
`MFA_STEPUP_MAX_AGE` seconds after logging in is challenged for that
action, because the RMB cookie is consulted only at login, not re-checked
by the step-up gate. This is expected, and a visible change for installs
that enabled RMB specifically to avoid challenges — see the 4.2.0 entry in
`CHANGELOG.md`.

This exists because a stolen or borrowed session could otherwise strip every
factor from an account and enrol its own without presenting anything.

### Per-IP rate limiting

`MFA_VERIFY_RATE_LIMIT` budgets guesses *per account*, which an attacker with a
list of stolen passwords simply routes around: one guess against each of ten
thousand accounts means every counter sits at 1 and none of them ever binds.
`MFA_VERIFY_IP_RATE_LIMIT` (new in 4.5.0, default `"50/5m"`) budgets the same
attempts per client address instead, so that run is stopped at 50.

Fifty *failed* second-factor attempts from one address in five minutes is far
outside normal use — a real user makes one to three — so the default is on. An
office behind a single NAT shares one budget, which is the case to think about
before leaving it as-is.

A successful verification clears the user's counter and deliberately **does
not** clear the IP's. An attacker only needs one account of their own to log
into, and clearing on success would hand them a fresh budget each time.

:::{warning}
The address comes from `REMOTE_ADDR`, and `X-Forwarded-For` is **not** read
unless you say so. That default is deliberate: a header the client sets breaks
the budget both ways — an attacker who varies it is never throttled, and one
who sets it to your office's address locks your staff out.

Behind a proxy or load balancer, `REMOTE_ADDR` is the *proxy*, so every request
shares one counter and the limit binds far too early. Point
`MFA_CLIENT_IP_RESOLVER` at a resolver that knows your topology:

    # settings.py
    MFA_CLIENT_IP_RESOLVER = "myapp.net.client_ip"

    # myapp/net.py -- one proxy hop, which we control and which always appends
    def client_ip(request):
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        return forwarded.rsplit(",", 1)[-1].strip() or None

Take the address your own infrastructure appended (the *last* entry), never the
first — the first is whatever the client sent. Returning `None` skips the per-IP
budget for that request; the per-user budget still applies.
:::

### `MFA_RATE_LIMIT_BACKEND`

Default: `"database"`.

`"database"` keeps counters in a `RateLimitCounter` table. `"cache"` keeps them
in Django's cache, which is what every release before 4.5.0 did.

The table is the default because a cache-only counter is erased by a Redis
restart, an eviction under memory pressure, or a `cache.clear()` somewhere in a
deploy script — and every erasure silently hands an attacker mid-run a fresh
budget, leaving no trace. The cost is one row read per verification attempt and
one write per *failed* one.

Rows are garbage once expired, and `manage.py mfa_prune` deletes them. Run it on
the same schedule as `django-admin clearsessions` — see {doc}`operations`.
`"cache"` needs no pruning and no migration, and remains a reasonable choice for
an install that would rather not add a write to the login path.

`MFA_RATE_LIMIT_FAIL_OPEN` covers the store being *unreachable* — a refused Redis
connection, a missing table — and nothing else. A counter that is simply absent
is indistinguishable from "nobody has failed yet" and is always allowed; a
limiter that denied on a cache miss would deny every first attempt ever made.

## Email codes

Only consulted when `"email"` is in `MFA_FACTORS`, which it is not by default —
add it to offer emailed one-time codes.

| Setting | Default | Purpose |
|---|---|---|
| `MFA_EMAIL_CODE_LENGTH` | `6` | Digits in an emailed code. |
| `MFA_EMAIL_CODE_VALIDITY` | `300` | How long an emailed code stays usable, in seconds. |
| `MFA_EMAIL_SUBJECT` | `None` | Subject line for the code email. `None` renders `django_mfa/email/otp_code_subject.txt`, which you can override instead. |
| `MFA_FROM_EMAIL` | `None` | From address for every email django-mfa sends. `None` falls back to Django's `DEFAULT_FROM_EMAIL`. |

Codes go to the address the factor was **enrolled with**, which the security
page shows masked — not to whatever `user.email` currently says. A factor is
possession of a specific mailbox; following a mutable profile field would mean
that whoever can change that field can redirect the factor. Changing the
address therefore means removing the factor and enrolling it again.

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
`MfaMiddleware` enforces two separate walls, and `MFA_EXEMPT_PATHS` is consulted by
both of them:

- An authenticated, not-yet-verified session is redirected to the second-factor
  picker, for every path except the ones derived automatically (the picker itself
  and each registered factor's verify page) plus whatever you list here.
- When `MFA_REQUIRED` applies to a user holding no primary factor, they are instead
  redirected to the security page, for every path except the enroll pages, recovery
  codes, and — again — whatever you list here. See {doc}`enforcement`.

Either wall traps a user with **no way to log out** unless your logout URL is
exempt: a pending user who cannot complete their second factor (lost device, no
recovery codes left), or a required user who cannot enroll one yet (no phone at
their desk, no security key issued). Every request they make, including to
`/logout/`, bounces back to a page that isn't where they were headed. django-mfa
cannot know your logout URL on its own; list it explicitly:

    MFA_EXEMPT_PATHS = ["/logout/"]

Paths are matched exactly against `request.path`, so include the full path as
mounted, with its trailing slash.
:::

## JSON API

| Setting | Default | Description |
|---|---|---|
| `MFA_API_AUTHENTICATION` | `None` | How {doc}`the JSON API <rest_api>` identifies the caller. `None` uses `request.user` — Django's own session authentication. Otherwise a callable taking a request and returning a user or `None`, or a dotted path to one, for clients that authenticate with a DRF token, a JWT or an API key. |

This setting is only consulted by `django_mfa.api`, which a project has to mount
explicitly; it does nothing on an install that never did. It answers *identity*
only — see {doc}`rest_api` for why MFA state still lives in the session, and what
that means for a client that discards cookies.

## System checks

django-mfa registers system checks that run on `manage.py check` — and therefore on
`migrate` and `runserver`, which run checks first — to catch the misconfigurations
described above before they can affect a real user.

E001–E003 are WebAuthn-only: they return no errors at all unless WebAuthn is
actually switched on for this install, meaning `MFA_QUICKLOGIN` is on or a WebAuthn
adapter is registered (true by default). A project with
`MFA_FACTORS = ["totp", "recovery_codes"]` never trips any of them.
`E004`–`E009` are not gated the same way — none of them is a WebAuthn setting, so
there is nothing to gate on, and they apply to every install regardless of which
factors are registered.

| Check ID | Severity | Condition |
|---|---|---|
| `django_mfa.E001` | Error | WebAuthn is active and `MFA_FIDO2_RP_ID` is unset. |
| `django_mfa.E002` | Error | WebAuthn is active and `MFA_FIDO2_RP_ID` is not a suffix of any `ALLOWED_HOSTS` entry. |
| `django_mfa.E003` | Error | WebAuthn is active and `django_mfa.backends.WebAuthnBackend` is missing from `AUTHENTICATION_BACKENDS`. |
| `django_mfa.E004` | Error | `MFA_REQUIRED` is a dotted path that fails to import, or resolves to a value that isn't callable. |
| `django_mfa.E005` | Error | `MFA_STEPUP_MAX_AGE` is not a positive integer or `None`. |
| `django_mfa.E006` | Error | `MFA_API_AUTHENTICATION` is a dotted path that fails to import, or resolves to a value that isn't callable. |
| `django_mfa.E007` | Error | `MFA_VERIFY_RATE_LIMIT`, `MFA_VERIFY_IP_RATE_LIMIT` or `MFA_EMAIL_SEND_RATE_LIMIT` is not a valid `"<count>/<window><unit>"` spec. |
| `django_mfa.E008` | Error | `MFA_RATE_LIMIT_BACKEND` is not `"database"` or `"cache"`. |
| `django_mfa.E009` | Error | `MFA_CLIENT_IP_RESOLVER` is a dotted path that fails to import, or resolves to a value that isn't callable. |

`E003` exists because the failure it prevents is otherwise completely silent.
Passwordless login logs a user in by calling `django.contrib.auth.login()` with an
explicit `backend=` argument, which succeeds regardless of `AUTHENTICATION_BACKENDS`.
The break only shows up one request later, when Django's own `get_user()` re-checks
that backend path against `AUTHENTICATION_BACKENDS` and, finding it absent, silently
resolves `request.user` to `AnonymousUser` — no exception, no log line, just a user
who was "logged in" a moment ago and is now anonymous again. Catching this at startup
is far cheaper than a support ticket.

All nine are `Error` rather than `Warning` deliberately, though what each guards
against differs slightly. E001–E003 guard a failure mode that is otherwise silent
in production (see E003's own explanation below). A misconfigured `MFA_REQUIRED`
is not silent even without E004 — `policy.resolve()` raises `ImproperlyConfigured`
or `ImportError` the first time `mfa_required_for()` runs, which is a loud 500 on
whichever live request gets there first. What E004 changes is *when* that failure
surfaces: at `manage.py check` (and therefore at `migrate`/`runserver`, and in CI if
you run checks there), before any request has been served, rather than as a 500 on
some user's request in production. E007–E009 are the same argument applied to the
rate limiter, where the timing is worse than usual: without them a bad spec or an
unimportable resolver raises from inside the *first verification attempt* after the
deploy, which is a 500 on the challenge page for whichever user happens to log in
first. If a check fires for a
reason you understand and have already accounted for — say you provision
`MFA_FIDO2_RP_ID` from a source Django's check framework can't see at check time —
the standard Django escape hatch applies:

    SILENCED_SYSTEM_CHECKS = ["django_mfa.E001"]

Prefer fixing the configuration (or narrowing `MFA_FACTORS`) over silencing one of
these. Silencing does not make the failure mode go away, only the warning about it.

## Signing stored secrets (deprecated)

:::{warning}
`MFA_SECRET_ENCRYPTION_KEYS` does not encrypt, despite the name. It **signs** the
stored value with `django.core.signing` under an `mfa1:` prefix. That is integrity,
not confidentiality: the payload is plain base64 and anyone with the database can
recover the TOTP secret without any key at all.

The setting is deprecated and kept only so values written by older versions keep
reading. Do not enable it expecting encryption at rest. If you need that, use your
database's own encryption, or a column-encryption library, and treat the TOTP secret
column as sensitive regardless.
:::

TOTP secrets are stored in the database in plaintext. Setting
`MFA_SECRET_ENCRYPTION_KEYS` to a list of one or more keys signs every secret written
from that point on, using the first key in the list, while still verifying anything
signed with an older key still present:

    MFA_SECRET_ENCRYPTION_KEYS = [
        "current-key",     # everything new is signed with this one
        "previous-key",    # still verifiable; drop once nothing uses it
    ]

That list *is* the rotation mechanism: add the new key at the front, redeploy, and
once nothing needs the old key anymore, drop it. There is no separate rotation
command to run.

Two limits worth knowing:

- **Existing values are not retroactively rewritten.** They are read unchanged and
  only signed the next time they're written — in practice, when the user re-enrolls.
- **Losing every key in the list makes those values unreadable *by django-mfa***,
  which locks affected users out of TOTP until they re-enroll. It does not make them
  unreadable by anyone else. Keep the keys wherever you keep `SECRET_KEY`.

WebAuthn credentials store no secret — only a public key — so this setting does not
apply to them. Recovery codes are hashed rather than encrypted, which is not
configurable.
