# Public API

The Python names a host project can rely on. Anything not on this page (adapter
internals, `django_mfa.otp`, `django_mfa.totp`, `django_mfa.flows`, the view
functions) is internal and can change without a deprecation period.

The URL configurations are `django_mfa.urls` (namespace `mfa`) and the opt-in
`django_mfa.api.urls` (namespace `mfa_api`). See {doc}`installation_setup` and
{doc}`rest_api`.

## Session state: `django_mfa.session`

Read and write MFA state through these functions, never through
`request.session["mfa"]`. The shape of that value is not part of the API.

```python
# myapp/views.py
from django_mfa import session

if session.is_verified(request):
    ...
```

| Function | Returns or does |
|---|---|
| `is_verified(request)` | `True` if this session has passed a second factor. Use this to decide whether to trust a session. |
| `is_pending(request)` | `True` if the session was marked pending at login and has not passed yet. `False` for a session that was never marked, so `not is_pending()` does not mean verified. |
| `verified_at(request)` | Unix timestamp (`int`) of the last successful challenge, or `None`. |
| `is_fresh(request, max_age)` | `True` if the session passed a challenge within the last `max_age` seconds. A verified session with no timestamp counts as stale. |
| `start_pending(request)` | Mark the session as waiting for a second factor. |
| `mark_verified(request, method)` | Mark it verified by `method` (a factor type string) and record the time. |
| `reset(request)` | Remove the MFA state from the session. |

You rarely need the last three: login marks the session pending, and the verify
views mark it verified.

## Factors: `django_mfa.registry`

```python
from django_mfa.registry import registry
```

| Method | Returns |
|---|---|
| `has_primary_factor(user)` | `True` if the user holds a factor that protects them on its own: one whose adapter has `counts_as_primary_factor = True`, which for the built-ins is everything except recovery codes. One query. This is the answer to "does this user have MFA". |
| `primary_enabled_for(user)` | The adapters behind that answer, as a list. One query per registered adapter. |
| `enabled_for(user)` | Adapters the user can verify with now, including recovery codes. What a challenge screen offers. |
| `available_for(user)` | Adapters the user could add now: enrollable factors, minus single-instance factors they already hold. Email is left out for a user with no usable address. |
| `all()` | Every registered adapter. |
| `get(type)` | The adapter for a type string. Raises `KeyError` if none is registered. |
| `register(adapter)` | Register an adapter instance. Raises `ValueError` if its type is taken. |
| `unregister(type)` | Remove an adapter. Raises `KeyError` if none is registered. |

Never decide whether to challenge a user from `enabled_for()`. A user holding only
recovery codes appears there but is not protected.

`django_mfa.registry.Adapter` is the base class for a factor type; see
{doc}`custom_factors`. The built-in adapters, which are also the `sender` of their
signals, are `django_mfa.adapters.totp.TOTPAdapter`,
`django_mfa.adapters.webauthn.WebAuthnAdapter`,
`django_mfa.adapters.recovery_codes.RecoveryCodesAdapter` and
`django_mfa.adapters.email.EmailAdapter`.

## Models

### `django_mfa.models.Authenticator`

One row per enrolled factor.

| Field | Notes |
|---|---|
| `user` | Foreign key to `AUTH_USER_MODEL`, related name `mfa_authenticators`. |
| `type` | `"totp"`, `"webauthn"`, `"recovery_codes"` or `"email"`: `Authenticator.Type.TOTP`, `.WEBAUTHN`, `.RECOVERY_CODES`, `.EMAIL`. |
| `name` | The label a user gives a security key or passkey. Empty for other types. |
| `data` | `JSONField` owned by the adapter. It holds the TOTP secret in readable form, so never display or log it. |
| `created_at`, `last_used_at` | `last_used_at` is `None` until the first successful verification. |

- `record_usage()` sets `last_used_at` to now. Adapters call it after a successful
  verification.
- `Authenticator.objects.for_user(user)` returns that user's rows.
- The database constraint `mfa_one_singleton_authenticator_per_user` allows at most
  one `totp`, one `recovery_codes` and one `email` row per user. `webauthn` rows are
  unlimited.

To remove every factor a user holds, use `manage.py mfa_reset <user>` (see
{doc}`operations`), which sends `factor_removed` for each row.
`Authenticator.objects.filter(user=user).delete()` removes them without any signal.

### `django_mfa.models.MfaExemption`

An operator's exemption of one user from `MFA_REQUIRED`. It is created by
`manage.py mfa_disable`, never by a web view; see {doc}`operations`.

| Field | Notes |
|---|---|
| `user` | One-to-one with `AUTH_USER_MODEL`, related name `mfa_exemption`. |
| `reason` | Required text. |
| `created_at` | When it was granted. |
| `expires_at` | `None` for permanent. Otherwise the exemption stops applying at this time. |

- `MfaExemption.objects.active_for(user)` returns the user's exemption if it is in
  force now, else `None`.
- `exemption.is_active()` is the same check on an instance.

An exemption lifts `MFA_REQUIRED` only. It does not open views protected by
`@mfa_required`.

## Enforcement

### `django_mfa.middleware.MfaMiddleware`

Add it after `django.contrib.auth.middleware.AuthenticationMiddleware`. For an
authenticated request it makes two checks, in this order:

1. **Pending.** If the session is pending, or was never challenged while the user
   holds a primary factor, it redirects to `mfa:verify`. The second case covers a
   session opened before the user enrolled their first factor (since 4.6.1).
   Exempt: the picker, each factor's verify page and `MFA_EXEMPT_PATHS`.
2. **Required but not enrolled.** If `MFA_REQUIRED` applies to the user and they hold
   no primary factor, it redirects to `mfa:security_settings`. Exempt: the enroll
   pages, the recovery codes page, the security page and `MFA_EXEMPT_PATHS`.

URLs in the JSON API's namespace pass both checks; the API applies them itself and
answers with status codes. `MFA_EXEMPT_PATHS` matches `request.path` exactly. To
skip a whole path prefix, subclass the middleware and override
`process_request()` (see {doc}`recipes`). The middleware also sets and clears the
`MFA_QUICKLOGIN` cookie. See {doc}`enforcement` for the full behaviour.

### `django_mfa.decorators`

| Name | Use |
|---|---|
| `@mfa_required` | The view needs a verified session. Sends an anonymous user to `LOGIN_URL`, a pending or never-challenged session to `mfa:verify`, and a user with no primary factor to `mfa:security_settings`. |
| `MfaRequiredMixin` | The same for a class-based view. Put it before the view class in the bases. |
| `@mfa_recent_required(max_age=None, next_url=None, allow_unenrolled=False)` | Everything `@mfa_required` checks, plus a challenge passed within `max_age` seconds (default `MFA_STEPUP_MAX_AGE`). Works bare or called. |
| `MfaRecentRequiredMixin` | The same for a class-based view, configured with the attributes `mfa_stepup_max_age`, `mfa_stepup_next_url` and `mfa_allow_unenrolled`. |

After a step-up challenge on a request other than `GET`, `HEAD`, `OPTIONS` or
`TRACE`, the user is sent to `next_url` (default `mfa:security_settings`), because
the request body cannot be replayed. `allow_unenrolled=True` lets a user with no
factor through; use it only on a view that enrolls a first factor. See
{doc}`enforcement`.

### `django_mfa.policy`

Who `MFA_REQUIRED` applies to. See {doc}`enforcement`.

| Name | Returns |
|---|---|
| `mfa_required_for(user)` | `True` if `MFA_REQUIRED` selects the user (plus every `is_staff` user when `MFA_PROTECT_ADMIN` is on), their grace period is over, and they have no active `MfaExemption`. It does not check whether they hold a factor. |
| `is_staff` | A predicate for `MFA_REQUIRED`: users with `is_staff` set. |
| `in_groups(*names)` | A new predicate for users in any of the named groups. Call it: `MFA_REQUIRED = in_groups("admins", "finance")`. |
| `required_at(user)` | When the requirement starts for this user: the later of `MFA_REQUIRED_FROM` and the user's grace anchor (`date_joined` unless `MFA_GRACE_ANCHOR` says otherwise) plus `MFA_GRACE_PERIOD`. `None` when neither applies. |
| `grace_state(user)` | A `GraceState` while the user would be required to enroll but is still inside their grace period, else `None`. |
| `GraceState` | A frozen dataclass with `required_at` (a datetime) and `days_remaining` (an `int`, rounded up, for display only). |

### `django_mfa.admin_site.MfaAdminMixin`

For an `AdminSite` subclass of your own. `MFA_PROTECT_ADMIN` applies the same
behaviour to `django.contrib.admin.site` only.

```python
# myproject/admin.py
from django.contrib import admin

from django_mfa.admin_site import MfaAdminMixin


class MyAdminSite(MfaAdminMixin, admin.AdminSite):
    pass
```

`has_permission()` also requires a verified session and a primary factor.
`login()` sends a signed-in user who fails those checks to `mfa:verify` or
`mfa:security_settings` instead of showing the admin login form. `MFA_ADMIN_STEPUP`
applies here too, but system check `django_mfa.E011` refuses it unless
`MFA_PROTECT_ADMIN` is also on. See {doc}`enforcement`.

### `django_mfa.context_processors.mfa`

Opt-in: add `"django_mfa.context_processors.mfa"` to the `context_processors` list
in your `TEMPLATES` setting. It adds `mfa_grace` to every template context: the
current user's `GraceState`, or `None` for anonymous users and anyone not in a
grace period. It is computed only if a template uses it.

```html+django
{% if mfa_grace %}
  <p>Set up two-factor authentication within {{ mfa_grace.days_remaining }} days.</p>
{% endif %}
```

There is no context processor for "is this session verified". Call
`session.is_verified(request)` in your view instead.

## Settings: `django_mfa.conf.settings`

Every django-mfa setting, with its default applied.

```python
from django_mfa.conf import settings as mfa_settings

mfa_settings.MFA_VERIFY_RATE_LIMIT  # "5/5m" unless your settings override it
```

Values are read from Django's settings on every access, so `override_settings()`
works in tests. A name that is not a django-mfa setting raises `AttributeError`.
See {doc}`settings`.

## Helpers

### `django_mfa.utils`

| Function | Purpose |
|---|---|
| `strings_equal(a, b)` | Constant-time string comparison: NFKC-normalises both, then uses `hmac.compare_digest`. Use it for every secret comparison in a custom factor. |
| `build_uri(secret, name, initial_count=None, issuer_name=None)` | An `otpauth://` provisioning URI: TOTP, or HOTP when `initial_count` is given. |

### `django_mfa.crypto` (deprecated)

These functions sign values; they do not encrypt them. Do not use them in new code.

| Function | Behaviour |
|---|---|
| `encrypt(value)` | Returns `value` unchanged when `MFA_SECRET_ENCRYPTION_KEYS` is unset. Otherwise returns `"mfa1:"` followed by `value` signed with the first key. The original is readable from the result without any key. |
| `decrypt(value)` | Returns a value without the `mfa1:` prefix unchanged. Otherwise checks the signature against each configured key in turn and returns the original. Raises `django.core.signing.BadSignature` if no key matches, including after the setting has been removed. |

A custom factor that needs a secret kept confidential has to encrypt it some other
way, such as a column-encryption library or database-level encryption. See
{doc}`security`.

### `django_mfa.handles`

WebAuthn user handles: a random UUID per user, stored in `MfaUserHandle`.

| Function | Returns |
|---|---|
| `user_handle_for(user)` | The user's handle as a string. Created on the first call, the same value afterwards. |
| `user_from_handle(handle)` | The user, or `None` for an unknown or malformed handle. Never raises. |

### `django_mfa.quicklogin`

For a login page that offers a returning visitor their passkey. Requires
`MFA_QUICKLOGIN = True`. `MfaMiddleware` already sets the cookie at login and
clears it at logout; these are for a flow of your own. See {doc}`recipes`.

| Name | Purpose |
|---|---|
| `COOKIE_NAME` | `"mfa_quicklogin"`. |
| `user_from_hint(value)` | The user the cookie value names, or `None`. Never raises. |
| `set_hint(response, user, secure)` | Sets the cookie (one year, `HttpOnly`, `SameSite=Lax`) and returns `response`. Does nothing when `MFA_QUICKLOGIN` is off. |
| `clear_hint(response)` | Deletes the cookie, whether or not the setting is on, and returns `response`. |

The cookie identifies an account; it authenticates nobody. Signing in still takes a
full passkey ceremony.

### `django_mfa.backends.WebAuthnBackend`

Required for passwordless login. Without it the user is anonymous again on the
request after signing in; `django_mfa.E003` catches the omission.

```python
# settings.py
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "django_mfa.backends.WebAuthnBackend",
]
```

`authenticate(request, mfa_user=None, **kwargs)` returns `mfa_user` and ignores
everything else, so a username and password passed down the backend chain never
authenticate anyone here. The passkey view validates the assertion before it calls
the backend. `get_user(user_id)` returns the user or `None`.

### `django_mfa.ratelimit`

Every verification already goes through these; they are public so your tests and
tools can inspect or reset budgets. `scope` is a factor type string such as
`"totp"`.

| Function | Purpose |
|---|---|
| `check(user, scope, setting="MFA_VERIFY_RATE_LIMIT")` | `True` if the user has budget left. `setting` names the budget to read. |
| `record_failure(user, scope, setting="MFA_VERIFY_RATE_LIMIT")` | Count one failure against it. `record` is the same function. |
| `clear(user, scope)` | Reset the user's counter, as a successful verification does. |
| `check_client(request, scope)` | `True` if the client address has budget left under `MFA_VERIFY_IP_RATE_LIMIT`. Also `True` when no address is known or the setting is `None`. |
| `record_client(request, scope)` | Count one failure against the client address. |
| `client_ip(request)` | The address that budget is charged to, or `None`. |
| `prune()` | Delete expired database counters and return how many were deleted. `manage.py mfa_prune` calls it. |

There is no `clear_client()`: a success never resets the per-address counter (see
{doc}`security`). To reset it in a test, delete the `RateLimitCounter` rows, or
clear the cache on the cache backend.

## Signals

Defined in `django_mfa.events` and also importable from `django_mfa.signals`.

| Signal | Keyword arguments | Sent when |
|---|---|---|
| `factor_added` | `user`, `authenticator`, `request` | A factor is enrolled (in the HTML views or the JSON API), or a new set of recovery codes is generated. `authenticator` is the new row. |
| `factor_removed` | `user`, `factor_type`, `name`, `request` | A user removes a factor, or `manage.py mfa_reset` removes one. The row is already deleted, so its type and name are passed as values. |
| `mfa_verified` | `user`, `method`, `request` | A second-factor challenge succeeds, including a passwordless sign-in whose assertion carries user verification. |
| `mfa_verification_failed` | `user`, `method`, `request` | A challenge fails: a wrong or malformed submission, or an attempt the rate limiter refused. Failed passwordless sign-ins do not send it. |
| `recovery_code_used` | `user`, `remaining`, `request` | A recovery code is spent. `remaining` is how many unused codes are left. |
| `mfa_exemption_changed` | `user`, `reason`, `expires_at`, `revoked`, `request` | `manage.py mfa_disable` grants or revokes an exemption. `reason` and `expires_at` are `None` on a revoke. |

- **`sender`** is the adapter class, for example `TOTPAdapter`, so you can connect
  with `sender=TOTPAdapter`. Two exceptions: `factor_removed` has `sender=None` when
  the removed type is no longer registered (match on `factor_type` instead), and
  `mfa_exemption_changed` always has `sender=MfaExemption`.
- **`request` is `None`** when a management command (`mfa_reset`, `mfa_disable`)
  sends the signal. Your receiver must handle that.
- **Read the user from the `user` argument**, not from `request.user`. During a
  passwordless sign-in, `mfa_verified` is sent before the user is logged in, while
  `request.user` is still anonymous.
- **A receiver cannot break the action it observes.** Signals are sent with
  `send_robust()`, which catches and discards your receiver's exceptions. Log your
  own failures.
- **Some deletions send nothing.** Deleting an `Authenticator` in the admin or with
  a queryset `delete()` sends no `factor_removed`. Connect `post_delete` on
  `Authenticator` if you need to see every deletion. Deleting an `MfaExemption` in
  the admin sends no `mfa_exemption_changed` either.

A receiver for an audit log:

```python
# myapp/signals.py
import logging

from django.dispatch import receiver

from django_mfa.signals import factor_removed

logger = logging.getLogger("myapp.security")


@receiver(factor_removed)
def audit_factor_removal(sender, user, factor_type, name, request, **kwargs):
    # request is None when manage.py mfa_reset removed the factor.
    source = request.META.get("REMOTE_ADDR") if request else "management command"
    logger.info("factor removed: user=%s type=%s name=%r from=%s",
                user.pk, factor_type, name, source)
```

Import the module from your app's `AppConfig.ready()` so the receiver is connected.
