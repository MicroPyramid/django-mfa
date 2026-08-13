# Public API

The Python surface a host project can depend on. Anything not listed here — the
adapters' internals, `django_mfa.otp`, `django_mfa.totp`, the view functions
themselves — is an implementation detail and may change without a deprecation cycle.

## `django_mfa.session`

Read and write the MFA state on a session. **Always use these** rather than touching
`request.session["mfa"]`: the dict's shape is not a public contract and has changed
once already.

| Function | Purpose |
|---|---|
| `is_verified(request)` | `True` if this session has completed a second factor. The one you'll actually use. |
| `is_pending(request)` | `True` if the session is awaiting a second factor. |
| `start_pending(request)` | Mark the session as awaiting verification. |
| `mark_verified(request, method)` | Mark it satisfied by `method` (a factor type string). |
| `reset(request)` | Remove MFA state entirely. |

Example:

    from django_mfa import session

    if session.is_verified(request):
        ...

You rarely need the writers: the `user_logged_in` receiver calls `start_pending()`
and the verify view calls `mark_verified()`.

## `django_mfa.registry`

The registry decides which factors exist and what each user holds. Import the
singleton — do not construct your own:

    from django_mfa.registry import registry

| Method | Returns |
|---|---|
| `primary_enabled_for(user)` | Adapters that mean this user **is protected**. Excludes recovery codes. **This is the predicate for "does this user have MFA".** |
| `has_primary_factor(user)` | The same question as a `bool`, in **one** query rather than one per registered adapter. Use this when you only need yes/no — the enrollment wall, `@mfa_required` and the notification receivers all do, and on a busy site the difference is per request. Both methods read `Adapter.counts_as_primary_factor`, so they cannot disagree. |
| `enabled_for(user)` | Adapters this user can **verify with right now**. Includes recovery codes. This is what to offer on a challenge screen. |
| `available_for(user)` | Adapters the user could still **add**. Excludes singletons they already hold and factors that aren't enrolled at all. |
| `all()` | Every registered adapter. |
| `get(type)` | One adapter by type string. Raises `KeyError` if absent. |
| `register(adapter)` | Add an adapter instance. Raises `ValueError` on a duplicate type. |
| `unregister(type)` | Remove one. Raises `KeyError` if it wasn't registered. |

The distinction between the first two is the one that matters. A user holding only
recovery codes appears in `enabled_for()` but not `primary_enabled_for()`, because
recovery codes are exhaustible and must never be someone's sole factor. Deciding
whether to challenge from `enabled_for()` would challenge users you cannot protect;
deciding what to offer from `primary_enabled_for()` would hide the recovery option
from exactly the people who need it.

`Adapter` is the base class for factor types — see {doc}`custom_factors`.

## `django_mfa.models.Authenticator`

One row per enrolled factor.

| Field | Notes |
|---|---|
| `user` | FK to `AUTH_USER_MODEL`, related name `mfa_authenticators`. |
| `type` | `"totp"`, `"webauthn"`, or `"recovery_codes"` — see `Authenticator.Type`. |
| `name` | User-supplied label. WebAuthn only, so several keys are distinguishable. |
| `data` | `JSONField` of factor-specific state. Shape is owned by the adapter; don't reach into it. |
| `created_at`, `last_used_at` | Timestamps. `last_used_at` is `None` until first use. |

`record_usage()` stamps `last_used_at`. Adapters call it on successful verification.

A database constraint (`mfa_one_singleton_authenticator_per_user`) allows at most one
`totp` and one `recovery_codes` row per user; WebAuthn is unlimited.

To remove a user's MFA — the administrative recovery path:

    Authenticator.objects.filter(user=user).delete()

## `django_mfa.conf.settings`

Resolved settings with defaults applied:

    from django_mfa.conf import settings as mfa_settings
    mfa_settings.MFA_VERIFY_RATE_LIMIT      # "5/5m" unless overridden

Asking for a name that isn't a django-mfa setting raises `AttributeError`, so typos
surface immediately. See {doc}`settings` for the full list.

## `django_mfa.utils`

| Function | Purpose |
|---|---|
| `strings_equal(a, b)` | Timing-safe comparison. Normalizes to NFKC, then `hmac.compare_digest`. Use for any secret comparison in a custom factor. |
| `build_uri(secret, name, initial_count=None, issuer_name=None)` | Build an `otpauth://` provisioning URI. |

## `django_mfa.crypto`

| Function | Purpose |
|---|---|
| `encrypt(value)` | Encrypt with the first `MFA_SECRET_ENCRYPTION_KEYS` entry. Returns `value` unchanged when the setting is unset. |
| `decrypt(value)` | Decrypt, trying every configured key. Passes through values stored before encryption was enabled. Raises `BadSignature` if no key works. |

Both are no-ops until a host project opts in, so a custom factor can use them
unconditionally and gain encryption the day someone sets the keys.

## `django_mfa.handles`

WebAuthn user handles — opaque, stored, `SECRET_KEY`-independent.

| Function | Purpose |
|---|---|
| `user_handle_for(user)` | The user's stable handle, creating it on first call. Idempotent. |
| `user_from_handle(handle)` | Resolve a handle back to a user, or `None`. Never raises — input is untrusted. |

## `django_mfa.quicklogin`

For a login page that offers a passkey to a returning visitor. Requires
`MFA_QUICKLOGIN = True`.

| Name | Purpose |
|---|---|
| `COOKIE_NAME` | `"mfa_quicklogin"`. |
| `user_from_hint(value)` | Resolve the cookie to a user, or `None`. Never raises. |
| `set_hint(response, user, secure)` | Attach the cookie. No-op when the setting is off. |
| `clear_hint(response)` | Remove it. Unconditional, so a stale cookie is cleaned up even after the feature is switched off. |

The cookie is a **UX hint, never a credential** — it identifies whose passkey prompt
to show and authenticates nobody. See {doc}`recipes`.

## `django_mfa.backends.WebAuthnBackend`

Required in `AUTHENTICATION_BACKENDS` for passwordless login. It performs no
cryptography: the view validates the assertion first, and the backend only returns
the already-resolved user through Django's standard contract.

`authenticate()` deliberately ignores `username`/`password` and returns a user only
when handed one explicitly as `mfa_user`, so another backend's call passing
credentials through the chain can never authenticate anyone here.

Omitting this backend breaks passkey login **silently, one request later** —
`django_mfa.E003` exists to catch that at startup.

## `django_mfa.middleware.MfaMiddleware`

Redirects authenticated-but-unverified requests to the picker. Its exempt set is
derived from the registry (the picker, plus each factor's verify page) unioned with
`MFA_EXEMPT_PATHS`. Subclass and override `process_request` to carve out a path
prefix — see {doc}`recipes`.

## `django_mfa.ratelimit`

Applied for you by the verify view; documented because a custom factor's tests may
need to reset it.

| Function | Purpose |
|---|---|
| `check(user, factor_type)` | `True` if another attempt is allowed. |
| `record_failure(user, factor_type)` | Count a failure. |
| `clear(user, factor_type)` | Reset the counter, as a success does. |

## Signals

django-mfa also **receives** `user_logged_in` (to stamp the session pending) and
`user_logged_out` (to clear the quicklogin hint) — you don't connect anything for
those, they're internal.

It **sends** five signals of its own, defined in `django_mfa.events` and re-exported
from `django_mfa.signals` (either import path works):

| Signal | kwargs | Fires when |
|---|---|---|
| `factor_added` | `user`, `authenticator`, `request` | An adapter's `complete_enroll()` succeeds — every ordinary enrollment, plus the first time a user generates recovery codes. `authenticator` is the created `Authenticator` row. |
| `factor_removed` | `user`, `factor_type`, `name`, `request` | `mfa:manage` deletes a row. `factor_type` and `name` are passed by value, not as an instance — the row is already gone by the time this fires. |
| `mfa_verified` | `user`, `method`, `request` | A second-factor challenge succeeds — from `verify_factor`'s success branch, and from `passkey_complete` when the passkey assertion carries User Verification (a UP-only passkey login logs the user in but has not satisfied a second factor, so it does not fire this). |
| `mfa_verification_failed` | `user`, `method`, `request` | A challenge fails: a wrong code, a caught adapter exception (`ValueError`/`TypeError`/`KeyError`), **or an attempt refused outright by the rate limiter** — no adapter call happens in that last case, so a receiver watching for brute force needs to see refused attempts too, not only evaluated ones. |
| `recovery_code_used` | `user`, `remaining`, `request` | A recovery code is spent. Sent from the adapter itself, not the view — only the adapter knows how many codes are left. |

Read the user off the `user` kwarg, never off `request.user`. On the passkey path
`mfa_verified` fires between `session.mark_verified()` and `auth.login()` — the
order is forced, since the login signal's own receiver checks whether the session is
already verified — so `request.user` is still `AnonymousUser` there, while the `user`
kwarg is correct on every path.

`sender` is the `Adapter` **class** for the factor involved (e.g. `TOTPAdapter`), so
a receiver can narrow with `sender=TOTPAdapter` — except on `factor_removed`, whose
`sender` is `None` when the removed row's type is no longer registered (`MFA_FACTORS`
was narrowed since it was enrolled, or a third-party adapter was unregistered): match
on the `factor_type` kwarg instead of `sender` if you need to handle that case.

A receiver:

    import logging

    from django.dispatch import receiver
    from django_mfa.signals import factor_removed

    logger = logging.getLogger("myapp.security")

    @receiver(factor_removed)
    def audit_factor_removal(sender, user, factor_type, name, request, **kwargs):
        logger.info("factor removed: user=%s type=%s name=%r",
                    user.pk, factor_type, name)

All five are sent with `send_robust()`, not `send()`: a raising receiver cannot break
the security action it's observing — enrolling, verifying, or removing a factor
succeeds or fails independently of what your receiver does with the event. The other
side of that trade is that `send_robust()` catches and discards the exception rather
than letting it propagate, so a receiver that fails does so **silently** unless it
logs its own failure.

To react with something other than a signal receiver, `post_save` on `Authenticator`
still works too — these signals are additional, not a replacement for the model
layer.
