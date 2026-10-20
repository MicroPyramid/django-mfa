# Settings reference

django-mfa settings are ordinary Django settings whose names start with `MFA_`; put
them in your settings module. The package reads them through
`django_mfa.conf.settings`, which returns the default shown here for any you leave
out and raises `AttributeError` for a name not on this page. A misspelt name in your
settings module is not caught (Django ignores settings nothing reads), so check
names against the tables below.

Most projects only set these:

```python
# settings.py
MFA_EXEMPT_PATHS = ["/accounts/logout/"]  # your logout URL, exactly as mounted
MFA_ISSUER_NAME = "Example"                # shown in authenticator apps
MFA_FIDO2_RP_ID = "example.com"            # your domain; never change it later
MFA_FIDO2_RP_NAME = "Example"              # shown by some security keys
```

While WebAuthn is on, which it is by default, `MFA_FIDO2_RP_ID` and
`django_mfa.backends.WebAuthnBackend` in `AUTHENTICATION_BACKENDS` are required.
See {doc}`installation_setup`.

## Core

| Setting | Default | What it does |
|---|---|---|
| `MFA_FACTORS` | `["totp", "recovery_codes", "webauthn"]` | Which built-in factors are offered. `"email"` is also available. See [`MFA_FACTORS`](#mfa_factors). |
| `MFA_EXEMPT_PATHS` | `[]` | Paths `MfaMiddleware` never redirects. Must include your logout URL; see [`MFA_EXEMPT_PATHS`](#mfa_exempt_paths). |
| `MFA_ISSUER_NAME` | `None` | Name shown next to the username in authenticator apps. Without it the app shows the username alone. |

### `MFA_EXEMPT_PATHS`

```python
# settings.py
MFA_EXEMPT_PATHS = ["/accounts/logout/"]
```

:::{warning}
Put your logout URL in this list. Without it, a user who cannot pass the challenge
(lost device, no recovery codes left), or a required user who cannot enroll yet, is
redirected on every request, including to your logout URL, and has no way to sign
out. django-mfa cannot discover your logout URL for you.
:::

- Paths match `request.path` exactly, not by prefix. Use the full path as mounted,
  with its trailing slash.
- The list applies to both of the middleware's redirects: to the challenge, and
  (under `MFA_REQUIRED`) to the security page. django-mfa's own challenge and
  enrollment pages are already exempt.
- A session that has not passed the challenge can reach every path listed, so list
  only pages that are safe for that.
- `@mfa_required` views and the admin gate ignore this list.

### `MFA_FACTORS`

```python
# settings.py: authenticator apps only, no security keys or passkeys
MFA_FACTORS = ["totp", "recovery_codes"]
```

Valid names are `"totp"`, `"webauthn"`, `"recovery_codes"` and `"email"`. The list
is read once, at startup, and an unknown name raises `ImproperlyConfigured` there.
Leaving out `"webauthn"` (with `MFA_QUICKLOGIN` off) also turns off system checks
E001–E003, so a TOTP-only project needs no `MFA_FIDO2_*` settings and no
`WebAuthnBackend`.

:::{warning}
Removing a factor from this list silently un-protects every user enrolled only in
that factor. Once `"totp"` is gone, a user whose only factor was TOTP logs in with
a password alone: nothing warns them or you, and their enrollment stays in the
database. Before you narrow the list, have those users enroll a factor you are
keeping. Recovery codes alone do not count.
:::

## Enforcement

| Setting | Default | What it does |
|---|---|---|
| `MFA_REQUIRED` | `False` | Who must hold a second factor: `False` (nobody), `True` (every signed-in user), a callable `(user) -> bool`, or a dotted path to one. `MfaMiddleware` sends a required user with no factor to the security page until they enroll. See {doc}`enforcement`. |
| `MFA_REQUIRED_FROM` | `None` | A `date` or `datetime` before which `MFA_REQUIRED` sends nobody to the security page. A `date` means midnight at its start. Does not delay `MFA_PROTECT_ADMIN` or `@mfa_required` views. |
| `MFA_GRACE_PERIOD` | `None` | Days (a number) or a `timedelta` that each user gets from their own start date. A user is required from the later of `MFA_REQUIRED_FROM` and start date plus this period. |
| `MFA_GRACE_ANCHOR` | `None` | Callable `(user) -> datetime or None`, or a dotted path to one, giving each user's start date. `None` uses `user.date_joined`. A user it returns `None` for gets `MFA_REQUIRED_FROM` alone. Needs `MFA_GRACE_PERIOD`. |
| `MFA_STEPUP_MAX_AGE` | `300` | Seconds a challenge stays fresh enough to add or remove factors. See [`MFA_STEPUP_MAX_AGE`](#mfa_stepup_max_age). |

### `MFA_STEPUP_MAX_AGE`

django-mfa's own pages for enrolling a factor, removing one, and recovery codes need
a challenge passed within the last `MFA_STEPUP_MAX_AGE` seconds. An older session is
sent through `mfa:verify` first. The same value is the default for
`@mfa_recent_required`, `MfaRecentRequiredMixin`, `MFA_ADMIN_STEPUP` and the JSON
API's factor-changing endpoints. See
[Step-up re-authentication](enforcement.md#step-up-re-authentication).

- `None` turns step-up off everywhere that uses this default, including
  `MFA_ADMIN_STEPUP`. A view that sets its own window keeps it:
  `@mfa_recent_required(max_age=60)` or `mfa_stepup_max_age = 60` on the mixin
  still enforces 60 seconds.
- Any other value must be a positive integer (`django_mfa.E005`).
- With `MFA_REMEMBER_MY_BROWSER` on, a trusted browser skips the challenge at login
  and that login counts as a fresh challenge for the next `MFA_STEPUP_MAX_AGE`
  seconds. After that, changing a factor asks for a challenge even on a trusted
  browser, because the cookie is only checked at login.

## Appearance

| Setting | Default | What it does |
|---|---|---|
| `MFA_BASE_TEMPLATE` | `"django_mfa/base.html"` | Template every django-mfa page extends. Point it at your own base template; see {doc}`customizing`. |

## Convenience

| Setting | Default | What it does |
|---|---|---|
| `MFA_REMEMBER_MY_BROWSER` | `False` | After a successful challenge, set a signed cookie so this browser skips the challenge on that user's later logins. Adding or removing any factor revokes every trusted browser. |
| `MFA_REMEMBER_DAYS` | `90` | How long a trusted-browser cookie lasts. Read only when `MFA_REMEMBER_MY_BROWSER` is on. |
| `MFA_QUICKLOGIN` | `False` | At login, set a one-year hint cookie identifying the account, so your login page can offer that user's passkey first. It never signs anyone in. Needs `MfaMiddleware`, and turns on checks E001–E003. See {doc}`recipes`. |

## Rate limiting

Limits are written `"<count>/<window><unit>"`, with unit `s`, `m` or `h`: `"5/5m"`
is five failures per five minutes. An attempt over a limit gets the same error as a
wrong code. Background in {doc}`security`.

| Setting | Default | What it does |
|---|---|---|
| `MFA_VERIFY_RATE_LIMIT` | `"5/5m"` | Failed attempts allowed per user, per factor type. A success clears it. |
| `MFA_VERIFY_IP_RATE_LIMIT` | `"50/5m"` | Failed attempts allowed per client address, per factor type, across all accounts. `None` turns it off. See [Per-IP rate limiting](#per-ip-rate-limiting). |
| `MFA_CLIENT_IP_RESOLVER` | `None` | Callable `(request) -> str or None`, or a dotted path to one, returning the client address. `None` uses `REMOTE_ADDR`. Set it behind a proxy. |
| `MFA_RATE_LIMIT_BACKEND` | `"database"` | Where counters live: `"database"` or `"cache"`. See [`MFA_RATE_LIMIT_BACKEND`](#mfa_rate_limit_backend). |
| `MFA_RATE_LIMIT_FAIL_OPEN` | `True` | When the counter store is unreachable, allow the attempt (`True`) or refuse it (`False`). |

### Per-IP rate limiting

`MFA_VERIFY_IP_RATE_LIMIT` stops one guess being tried against thousands of
accounts, which the per-user limit never sees. A successful verification does not
clear it. Everyone behind one NAT shares a budget; raise the limit if a large office
trips it.

The address is `REMOTE_ADDR`. `X-Forwarded-For` is not read by default because the
client controls it: varying it dodges the limit, and forging your office's address
locks your staff out. Behind a proxy or load balancer, `REMOTE_ADDR` is the proxy,
so every client shares one counter. Tell django-mfa where the real address is:

```python
# settings.py
MFA_CLIENT_IP_RESOLVER = "myproject.net.client_ip"
```

```python
# myproject/net.py
def client_ip(request):
    # One proxy that you run, which appends the address it saw to
    # X-Forwarded-For. Take the last entry: earlier ones come from the client.
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    return forwarded.rsplit(",", 1)[-1].strip() or None
```

With more than one proxy of your own in front of Django, take the entry that many
places from the end. Returning `None` skips the per-IP limit for that request; the
per-user limit still applies.

### `MFA_RATE_LIMIT_BACKEND`

`"database"` keeps counters in the `RateLimitCounter` table: one read per attempt
and one write per failure. Expired rows stay until you delete them, so schedule
`manage.py mfa_prune` alongside `clearsessions`; see {doc}`operations`.

`"cache"` keeps counters in Django's default cache and needs no pruning. A cache
restart, eviction or `cache.clear()` wipes every counter and gives an attacker a
fresh budget. Use a cache that all your processes share, such as Redis or
Memcached: `LocMemCache` counts each process separately, and `FileBasedCache` loses
increments from parallel attempts.

`MFA_RATE_LIMIT_FAIL_OPEN` covers either store failing (database down, table
missing, cache unreachable). A counter that does not exist yet always means "no
failures" and is never refused.

## Email codes

Read only when `"email"` is in `MFA_FACTORS`, which it is not by default.
`MFA_FROM_EMAIL` also applies to notifications.

| Setting | Default | What it does |
|---|---|---|
| `MFA_EMAIL_CODE_LENGTH` | `6` | Digits in an emailed code. |
| `MFA_EMAIL_CODE_VALIDITY` | `300` | Seconds an emailed code stays valid. |
| `MFA_EMAIL_SEND_RATE_LIMIT` | `"3/5m"` | Codes one user can be sent per window. Reloading the page reuses a code that is still valid. Past the limit no mail is sent and the page looks the same. |
| `MFA_EMAIL_SUBJECT` | `None` | Subject line of the code email. `None` renders the template `django_mfa/email/otp_code_subject.txt`. |
| `MFA_FROM_EMAIL` | `None` | Sender of every email django-mfa sends, codes and notifications. `None` uses `DEFAULT_FROM_EMAIL`. |

Codes go to the address the user enrolled with, not to whatever their profile says
now. To change it, the user removes the factor and enrolls again.

## Notifications

| Setting | Default | What it does |
|---|---|---|
| `MFA_NOTIFY_ON_CHANGE` | `False` | Email the user when a factor is added or removed, when a recovery code is used, and when a removal leaves them with no factor except recovery codes. Sent during the request; a failure is logged, not raised. |

The `django_mfa.events` signals fire whether or not this is on. To deliver these
messages another way, leave it off and connect your own receiver; see {doc}`api`.

## WebAuthn

You can skip this section if you leave `"webauthn"` out of `MFA_FACTORS` and keep
`MFA_QUICKLOGIN` off.

| Setting | Default | What it does |
|---|---|---|
| `MFA_FIDO2_RP_ID` | `None` | Your registrable domain, such as `"example.com"`. Required while WebAuthn is on. Never change it once keys are registered; see [`MFA_FIDO2_RP_ID`](#mfa_fido2_rp_id). |
| `MFA_FIDO2_RP_NAME` | `"django-mfa"` | Site name some authenticators show while registering. Set it to your product name. |
| `MFA_FIDO2_RESIDENT_KEY` | `"preferred"` | `residentKey` for registration: `"required"`, `"preferred"` or `"discouraged"`. Passwordless login needs a discoverable credential, so do not use `"discouraged"` if you offer it. |
| `MFA_FIDO2_USER_VERIFICATION` | `"preferred"` | `userVerification` for every ceremony: `"required"`, `"preferred"` or `"discouraged"`. A passkey login counts as the second factor only when the authenticator checked a PIN or biometric; `"required"` makes that always so. See {doc}`mfa_flow`. |
| `MFA_FIDO2_AUTHENTICATOR_ATTACHMENT` | `None` | Limit registration to `"platform"` (Touch ID, Windows Hello) or `"cross-platform"` (USB or NFC keys). `None` allows both. |
| `MFA_FIDO2_ATTESTATION_PREFERENCE` | `"none"` | `attestation` conveyance: `"none"`, `"indirect"` or `"direct"`. Leave it at `"none"` unless you must collect attestation; `"direct"` can make the browser ask the user for permission. |
| `MFA_OWNED_BY_ENTERPRISE` | `False` | Stop users removing their own security keys and passkeys, from the security page or the JSON API. For keys your organization issues and manages. |

### `MFA_FIDO2_RP_ID`

Set it once, before anyone registers a key:

```python
# settings.py
MFA_FIDO2_RP_ID = "example.com"
```

:::{warning}
Every security key and passkey is bound to the RP ID it was registered under.
Changing the value later makes all of them unusable, and there is no migration:
each user has to remove theirs and register again. Treat a change as revoking every
WebAuthn credential on the site.
:::

The value must equal the host that serves your pages or be a parent domain of it:
`"example.com"` works for both `example.com` and `app.example.com`. System checks
E001 and E002 report it missing or not matching `ALLOWED_HOSTS`.

## JSON API

Read only if you mount `django_mfa.api.urls`.

| Setting | Default | What it does |
|---|---|---|
| `MFA_API_AUTHENTICATION` | `None` | How {doc}`the JSON API <rest_api>` identifies the caller. `None` uses `request.user`. Otherwise a callable `(request) -> user or None`, or a dotted path to one, for DRF tokens, JWTs or API keys. It sets identity only; MFA state stays in the session. |

## Admin

| Setting | Default | What it does |
|---|---|---|
| `MFA_PROTECT_ADMIN` | `False` | Every page of the default admin site (`django.contrib.admin.site`) needs a factor and a passed challenge, and `MFA_REQUIRED` also applies to staff. Works without `MfaMiddleware`. See {doc}`enforcement`. |
| `MFA_ADMIN_STEPUP` | `False` | With `MFA_PROTECT_ADMIN` on, admin pages also need a challenge within `MFA_STEPUP_MAX_AGE`. On its own it does nothing (`django_mfa.E011`). |

`MFA_PROTECT_ADMIN` covers only the default site. If you mount your own `AdminSite`
instance, mix `django_mfa.admin_site.MfaAdminMixin` into its class instead.

## Deprecated

| Setting | Default | What it does |
|---|---|---|
| `MFA_SECRET_ENCRYPTION_KEYS` | `None` | Signs stored TOTP secrets. It does not encrypt them. See [`MFA_SECRET_ENCRYPTION_KEYS`](#mfa_secret_encryption_keys). |

### `MFA_SECRET_ENCRYPTION_KEYS`

:::{warning}
Despite the name, this setting does not encrypt anything. It signs each TOTP secret
with `django.core.signing` under an `mfa1:` prefix, which protects integrity, not
confidentiality: anyone with the database can read the secret without a key. Treat
TOTP secrets as stored in plaintext. For encryption at rest, use your database's
encryption or a column-encryption library.
:::

The setting is kept so that values written by older versions can still be read.
New secrets are signed with the first key, and reading tries every key in turn, so
you rotate by putting a new key first:

```python
# settings.py
MFA_SECRET_ENCRYPTION_KEYS = [
    "current-key",   # signs new values
    "previous-key",  # still accepted when reading
]
```

- Existing values are not rewritten; a secret is signed when the user next enrolls
  TOTP.
- An `mfa1:` value whose key is no longer in the list cannot be read, and that user
  cannot verify with TOTP until they enroll again. Keep the setting, with the key
  that signed them, while any such values remain.

## System checks

These checks run with `manage.py check` and before most other management commands,
including `migrate` and `runserver`, but not when a WSGI or ASGI server starts, so
run `manage.py check` in CI or as a deploy step. All of them are errors.

E001–E003 run only while WebAuthn is on: `"webauthn"` is in `MFA_FACTORS` (the
default) or `MFA_QUICKLOGIN` is `True`. The rest apply to every install.

| Check | Fails when |
|---|---|
| `django_mfa.E001` | `MFA_FIDO2_RP_ID` is not set. |
| `django_mfa.E002` | `MFA_FIDO2_RP_ID` matches no `ALLOWED_HOSTS` entry, either exactly or as a parent domain. Skipped when `ALLOWED_HOSTS` is empty or holds only `"*"`. |
| `django_mfa.E003` | `django_mfa.backends.WebAuthnBackend` is not in `AUTHENTICATION_BACKENDS`. |
| `django_mfa.E004` | `MFA_REQUIRED` is not `True`, `False`, `None`, a callable, or a dotted path that imports to a callable. |
| `django_mfa.E005` | `MFA_STEPUP_MAX_AGE` is not a positive integer or `None`. |
| `django_mfa.E006` | `MFA_API_AUTHENTICATION` is set, but is not a callable or a dotted path that imports to one. |
| `django_mfa.E007` | `MFA_VERIFY_RATE_LIMIT`, `MFA_VERIFY_IP_RATE_LIMIT` or `MFA_EMAIL_SEND_RATE_LIMIT` is not a valid `"<count>/<window><unit>"`, or has a zero count or window. Only `MFA_VERIFY_IP_RATE_LIMIT` may be `None`. |
| `django_mfa.E008` | `MFA_RATE_LIMIT_BACKEND` is not `"database"` or `"cache"`. |
| `django_mfa.E009` | `MFA_CLIENT_IP_RESOLVER` is set, but is not a callable or a dotted path that imports to one. |
| `django_mfa.E010` | Grace is set up but cannot work: `MFA_REQUIRED_FROM` is not a `date` or `datetime`; `MFA_GRACE_PERIOD` is negative, or not a number or `timedelta`; `MFA_GRACE_PERIOD` has no start date to count from (no `MFA_GRACE_ANCHOR`, and no `date_joined` on the user model); or `MFA_GRACE_ANCHOR` does not import, is not callable, or is set without `MFA_GRACE_PERIOD`. |
| `django_mfa.E011` | `MFA_ADMIN_STEPUP` is on but `MFA_PROTECT_ADMIN` is not, so the admin is unprotected. |

If a check fires for a reason you have already handled, silence it by ID. That
hides the error without fixing its cause, so prefer correcting the setting, or
leaving `"webauthn"` out of `MFA_FACTORS` if you do not use it.

```python
# settings.py
SILENCED_SYSTEM_CHECKS = ["django_mfa.E002"]
```

E003 matters because the failure it catches is otherwise invisible. Passkey login
passes `WebAuthnBackend` to `login()` explicitly, which works even when the backend
is missing from `AUTHENTICATION_BACKENDS`. On the next request Django does not find
the session's backend in that setting and treats the user as anonymous. Nothing is
raised or logged: the user signs in with a passkey and is signed out one click
later. Add the backend:

```python
# settings.py
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "django_mfa.backends.WebAuthnBackend",
]
```
