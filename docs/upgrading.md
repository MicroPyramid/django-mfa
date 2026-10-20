# Upgrading

Which parts of this page you need depends on the version you are upgrading from.

**From 2.x or 3.x.** Version 4.0 is a ground-up rewrite: U2F support is gone, TOTP and WebAuthn/passkey support are built around a single polymorphic `Authenticator` model instead of one table per factor, and several URLs, session keys, and settings from earlier releases no longer exist. Read sections 1–12 in full before upgrading a project that has real users with MFA already enabled, in particular [section 8](#8-migration-0007-is-irreversible-roll-back-from-a-backup-not-migrate) on migration `0007`, which is **irreversible**. Then read the release sections that follow them (4.2.0 onwards), because you are crossing those releases too.

**From one 4.x release to a later one.** Read the release sections (4.2.0, 4.5.0, 4.6.1) for each release you cross, and section 12 if you are coming from 4.0.0. They cover the changes that need action from you or change behaviour. {doc}`changelog` has the full notes for every release from 4.1.0 on, including the smaller changes that need nothing from you.

## 1. Django 4.2+ and Python 3.10+ are now required

Earlier releases supported Django 2.2–3.2 and Python 3.6–3.10. django-mfa 4.x requires Django 4.2 or later and Python 3.10 or later; the current release supports Django 4.2, 5.2 and 6.1 on Python 3.10–3.13 (see `pyproject.toml`). Django 6.1 also needs Python 3.12+, which is Django's own floor. The old code could not run on a newer Django at all: it imported `django.utils.http.is_safe_url` and `django.utils.translation.ugettext`, both removed in Django 4.0. So there is no supported path that runs both the old and new code against the same Django version, and the Django/Python upgrade and the django-mfa upgrade have to happen together.

## 2. U2F support is removed entirely

U2F (the `U2FKey` model, `python-u2flib-server` dependency, and every `u2f`-prefixed view/URL) is gone. There is no migration path for previously registered U2F keys: migration `0007_drop_legacy_models` drops the `U2FKey` table outright, and no prior migration ever copied U2F registrations onto the new `Authenticator` model (unlike TOTP and recovery codes; see the next section). **Every user whose only second factor was a U2F key loses that factor on upgrade and must re-enroll** with TOTP or a WebAuthn security key/passkey (which is the modern, browser-native successor to U2F and covers the same "physical security key" use case). Warn your users before upgrading if any of them rely on U2F today.

## 3. `UserOTP`, `UserRecoveryCodes`, and `U2FKey` are replaced by `Authenticator`

The three old models are gone from `django_mfa/models.py`. In their place:

- `Authenticator`: one polymorphic model for every factor type (`type` is `"totp"`, `"webauthn"`, `"recovery_codes"`, or the opt-in `"email"`), factor-specific data in a `data` `JSONField`, and a `user` FK. A user can hold multiple `Authenticator` rows (e.g. several WebAuthn keys), but at most one `totp`, one `recovery_codes`, and one `email` row each (a database constraint enforces this; migration `0008_email_factor` extended it from `totp`/`recovery_codes` to also cover `email` when that factor was added).
- `MfaUserHandle` (`django_mfa/handles.py`): a new model, one row per user, holding the stable opaque WebAuthn "user handle" passkey ceremonies use to resolve a user before any password is typed. Created lazily, the first time a user's handle is needed.

Migration `0005_migrate_to_authenticator` copies every existing `UserOTP` row to an `Authenticator` row of type `totp`, and every user's `UserRecoveryCodes` rows to a single `Authenticator` row of type `recovery_codes` holding all of that user's codes together (see item 10 below for what state those codes are in afterwards). Migration `0007` then drops the old tables (see item 8).

If your project queries `UserOTP`/`UserRecoveryCodes`/`U2FKey` directly (rather than only through django-mfa's own views), that code must be updated to query `Authenticator` instead before upgrading.

## 4. `request.session["verfied_otp"]`/`["verfied_u2f"]` are replaced by `request.session["mfa"]`

The old middleware tracked verification state in two separate, historically **misspelled** session keys, `verfied_otp` and `verfied_u2f` (not "verified"). Both are gone. There is now a single `request.session["mfa"]` dict:

```python
{"verified": bool, "method": str | None, "at": int | None}
```

It is managed entirely through `django_mfa.session` (`start_pending()`, `mark_verified()`, `is_verified()`, `is_pending()`, `reset()`). Do not read or write `request.session["mfa"]` directly from host-project code; use those functions, since the shape of the dict is not a public contract. If any host-project code inspected the old keys directly (e.g. to customise a template based on MFA status), update it to use `django_mfa.session.is_verified(request)` instead.

## 5. Nine URL names are gone

| Removed name | Replaced by |
|---|---|
| `verify_second_factor` | `mfa:verify` (the factor picker) |
| `verify_second_factor_totp` | `mfa:verify_factor` with `factor_type="totp"` |
| `verify_second_factor_u2f` | nothing; U2F is gone (see item 2) |
| `u2f_keys` | nothing; U2F is gone |
| `add_u2f_key` | nothing; U2F is gone |
| `configure_mfa` | `mfa:enroll_factor` with `factor_type="totp"` |
| `enable_mfa` | `mfa:enroll_factor` (enrolling *is* enabling) |
| `disable_mfa` | `mfa:manage` (POST, deletes one authenticator) |
| `recovery_codes_download` | nothing: the download is now built client-side from the codes already in the `mfa:recovery_codes` page (see `recovery_codes.html`), so the server never serves plaintext codes a second time. |

`mfa:security_settings` and `mfa:recovery_codes` keep their old names (their URLs/views changed, but not what host projects call them by). Any `{% url %}` tag, hardcoded link, or `reverse()` call in your project referencing a removed name will raise `NoReverseMatch` after upgrading. Search your templates and Python code for the names in the left column above before deploying.

## 6. Host projects no longer set `u2f_pre_verify_user_pk`/`u2f_pre_verify_user_backend`

Under the old U2F contract, a host project's own login view had to stash `request.session['u2f_pre_verify_user_pk']` and `['u2f_pre_verify_user_backend']` by hand *before* calling `django.contrib.auth.login()`, so the (U2F-specific) verify view could rebuild the pending user from those keys. That contract is gone along with U2F itself. A `user_logged_in` signal receiver (`django_mfa.signals.stamp_pending_verification`) now marks the session as awaiting a second factor on every login by a user who holds one, whichever view performed the login and whichever authentication backend was used. **Remove any code your login view has that sets those two session keys.** The new receiver does not read them, so leaving that code in place is harmless but pointless.

## 7. `MFA_FIDO2_RP_ID` is now required for WebAuthn

New setting. It is required whenever WebAuthn is enabled, which it is by default (`MFA_FACTORS` includes `"webauthn"`), and whenever `MFA_QUICKLOGIN` is on. There is no sensible default django-mfa could pick on your behalf: it must be your registrable domain. Django's system checks (run by `manage.py check`, `migrate` and `runserver`) fail if it is unset (`django_mfa.E001`), or set to something that isn't a suffix of any `ALLOWED_HOSTS` entry (`django_mfa.E002`); see [System checks](settings.md#system-checks). If you do not want to offer security keys or passkeys, remove `"webauthn"` from `MFA_FACTORS` instead.

:::{warning}
Set this once and do not change it later. WebAuthn credentials are cryptographically bound to the RP ID at registration time; changing it invalidates every previously registered security key and passkey, with no way to migrate them.
:::

## 8. Migration `0007` is irreversible: roll back from a backup, not `migrate`

`0007_drop_legacy_models` drops the `UserOTP`, `UserRecoveryCodes`, and `U2FKey` tables. It is marked **irreversible**: running `migrate django_mfa 0006` (or further back) after `0007` has been applied raises `IrreversibleError` and refuses to touch the database.

This is intentional, not a limitation left unfixed. Django's auto-generated reverse for a dropped table only recreates the table's *schema*; it cannot un-drop the table and bring back the rows that were in it. That looks like a cosmetic gap ("the table comes back empty") until you consider the full rollback sequence a backwards `migrate` would perform. Unwinding `0007` recreates empty `UserOTP`/`UserRecoveryCodes` tables, and unwinding `0005` right after it *deletes every* `Authenticator` *row that migration created* (it assumes the original legacy rows it copied from are "still present and untouched", which is true only if `0007` was never applied). The end state: every migrated user's TOTP secret and recovery codes are gone from **both** places at once, and no step in that sequence raises an error, so the operator sees every migration report success. `0007` blocks exactly that sequence from being possible.

**If you need to roll back an upgrade that has already applied migration 0007, the only correct way is to restore a database backup taken before the upgrade ran.** Take that backup *before* running `migrate` as a matter of course for this upgrade specifically. Do not rely on being able to `migrate` your way back out: once `0007` has run, the pre-migration TOTP secrets and recovery codes exist nowhere else for Django to restore them from.

U2F registrations were never copied onto `Authenticator` in the first place (see item 2), so they have no forward path regardless of this migration's reversibility. This item is only about the TOTP and recovery-code data that migration `0005` did copy forward.

## 9. TOTP now tolerates a small clock/window drift

The old TOTP verification used zero tolerance: a code was only accepted in the exact 30-second window the server computed at that instant. 4.x accepts the previous and next 30-second code as well as the current one (`TOTP_VALID_WINDOW = 1` in `django_mfa/adapters/totp.py`), matching django-otp's default. This is strictly more permissive than before. It fixes spurious rejections from phone clock drift or a user submitting right at a window boundary, and cannot cause a previously accepted code to be rejected, so no action is required. It is still worth knowing that the acceptance window widened: three codes are valid at any moment instead of one, which makes each guess three times as likely to succeed. Rate limiting (see `MFA_VERIFY_RATE_LIMIT`) already accounts for this.

## 10. Recovery codes are hashed at rest, except migrated codes until they are regenerated

Recovery codes generated by 4.x are hashed at rest (via Django's own password hasher) and, like a password, can never be displayed again: they are shown only once, at generation time. Codes carried forward by migration `0005` from a pre-upgrade `UserRecoveryCodes` table are the one exception. They were stored in plaintext under the old schema, and the migration copies them across *as plaintext*, marking that `Authenticator` row with `data["migrated_plaintext"] = True` so verification (`django_mfa/adapters/recovery_codes.py`) knows to compare them directly instead of via the password hasher. **Those specific codes remain plaintext in the database until the user regenerates them**; upgrading does not hash anything that was already stored. There is no dedicated "regenerate my recovery codes" control in the UI: the user removes the recovery-codes authenticator via `mfa:manage` and revisits `mfa:recovery_codes`, which then generates a fresh, hashed set. If this matters for your threat model, prompt affected users to do exactly that after upgrading, or run a one-off script that does the same for every user with `data["migrated_plaintext"]` set.

## 11. Passwordless login requires adding `WebAuthnBackend` to `AUTHENTICATION_BACKENDS`

New in 4.0. If you want users to be able to sign in with a passkey alone (no password, no separate second-factor step), add:

```python
# settings.py
AUTHENTICATION_BACKENDS = [
    "django_mfa.backends.WebAuthnBackend",
    "django.contrib.auth.backends.ModelBackend",
    # ... any other backends your project already used
]
```

Passwordless login (`mfa:passkey_begin`/`mfa:passkey_complete`) is exposed by `django_mfa.urls` unconditionally; there is no setting that turns the URLs themselves off. If a user manages to register a WebAuthn credential and this backend is missing, the login *appears* to succeed (`auth.login()` doesn't validate the backend it's given against `AUTHENTICATION_BACKENDS`) and then silently, permanently degrades that session to `AnonymousUser` on the very next request, with no error anywhere. Django's system checks now catch this at startup (`django_mfa.E003`, see [System checks](settings.md#system-checks)) whenever `MFA_QUICKLOGIN` is on or a WebAuthn adapter is registered (true by default), so a project missing this backend will fail to start rather than fail silently in production.

## 12. Security fixes in 4.0.1 that change observable behaviour

These are fixes to real defects in 4.0.0. All are worth knowing about before you upgrade, but only the last two need any action from you.

- **TOTP codes can now be redeemed only once** (RFC 6238 §5.2). 4.0.0 accepted the same code repeatedly for as long as it stayed inside the ±1 window, roughly 90 seconds. The accepted time step is now recorded in `Authenticator.data["last_verified_counter"]` and any code at or below it is refused. The key appears lazily on first use; no migration is involved. The only user-visible effect is that double-submitting the verification form now fails the second time.

- **New TOTP secrets are 160-bit and come from `secrets`**, not 80-bit values from the `random` module. Existing enrollments are untouched and keep working, since an 80-bit secret is still a valid TOTP secret. Users who want the longer secret must re-enroll. Consider prompting them to if your threat model includes an attacker who can observe other output of the same process's `random` module.

- **Recovery-code consumption, TOTP redemption and WebAuthn sign-count updates are now race-free.** All three were read-modify-write on the `data` blob, so two simultaneous requests could lose one another's writes. That could spend a recovery code twice, or drag a WebAuthn signature counter backwards and defeat clone detection. They now use a compare-and-set (`django_mfa.atomic.update_data`).

- **The rate-limit window is fixed rather than sliding.** In 4.0.1 the cache counter switched to `cache.add()` + `cache.incr()`, so parallel attempts cannot overwrite each other's increments. A side effect is that the window now runs from the first failure instead of being extended by each subsequent one, so a lockout ends slightly sooner than before. Since 4.5.0 the counters live in the database by default (see the 4.5.0 section below), so the cache only matters if you set `MFA_RATE_LIMIT_BACKEND = "cache"`. In that case use Redis or Memcached: **`FileBasedCache` and `DatabaseCache` have no atomic `incr()` and must not be used for this.**

- **`MFA_REMEMBER_MY_BROWSER` now works for every factor type, and every existing trusted browser is re-challenged once.** The cookie salt used to be derived from the user's TOTP secret, so the feature silently did nothing for users whose only factor was a security key or passkey. It is now derived from the user's whole set of enrolled factors. Because the salt changed, cookies issued by 4.0.0 no longer verify: affected users see one extra second-factor challenge after you deploy, and are then trusted again. Enrolling or removing any factor now also invalidates previously trusted browsers, which it did not reliably do before.

- **`Authenticator` is no longer editable in the Django admin.** It is registered read-only, with add and change disabled and `data` excluded from every field, changelist and search list. Before this, a staff account with `view_authenticator` could read (and with `change_authenticator`, overwrite) another user's TOTP secret. Deleting is still allowed, so revoking a lost authenticator for a locked-out user still works. **If your project relied on editing `Authenticator` rows through the admin, that will now fail**; register your own `ModelAdmin` if you genuinely need it, and keep `data` out of it.

Separately, the documentation for `MFA_SECRET_ENCRYPTION_KEYS` was wrong: it described the setting as encrypting TOTP secrets at rest. It does not encrypt. It signs them with `django.core.signing`, which provides integrity only: the payload is plain base64 and recovers without any key, so TOTP secrets are effectively stored in plaintext whether or not the setting is on. The setting is now deprecated. Nothing about the code changed in 4.0.1; see {doc}`settings` and {doc}`security` for the corrected description, and re-check any risk assessment that relied on the old wording.

## 4.2.0: factor changes now require a recent challenge

Run `manage.py migrate`: migration `0009` adds the `MfaExemption` table.

`enroll_factor`, `manage_factors` and `recovery_codes` are gated on
`MFA_STEPUP_MAX_AGE` (default 300 seconds). A user who verified more than
five minutes ago is redirected through `mfa:verify` before the change is
accepted.

This is the one place 4.2.0 does not upgrade to byte-identical behaviour. The
alternative would leave the hole open for every install that does not read
this page. Set `MFA_STEPUP_MAX_AGE = None` to restore 4.1.0 behaviour exactly.

The verification picker now also honours `?next=`, so a single-factor user is
returned to the page they requested after logging in rather than to
`LOGIN_REDIRECT_URL`.

## 4.5.0: rate-limit counters move to the database, and two behaviour changes

**Run `manage.py migrate`.** Migration `0010` adds `RateLimitCounter`, and
`MFA_RATE_LIMIT_BACKEND` defaults to `"database"`, so the table is in use from
the first request after the upgrade. If you deploy code before migrations, set
`MFA_RATE_LIMIT_BACKEND = "cache"` for that window. With the default
`MFA_RATE_LIMIT_FAIL_OPEN = True` the rate limiter fails open on a store it
cannot reach, so a missing table means unthrottled verification rather than an
outage, and nothing tells you.

Then schedule the new `manage.py mfa_prune` alongside `django-admin
clearsessions`. Nothing breaks without it; the table grows forever, and the
per-IP budget puts client addresses in it.

Two changes are visible without any configuration:

**A per-IP verification budget is now enforced**, `MFA_VERIFY_IP_RATE_LIMIT`,
default `"50/5m"`. Fifty *failed* second-factor attempts from one address in
five minutes is far outside normal use, so most installs will never notice. Two
that will:

- **You run behind a proxy or load balancer.** `REMOTE_ADDR` is then the proxy,
  every client shares one counter, and the budget binds far too early. Set
  `MFA_CLIENT_IP_RESOLVER` (see {doc}`settings`). django-mfa does not read
  `X-Forwarded-For` for you: a client-set header would let an attacker both
  evade the budget and exhaust somebody else's.
- **Your users share one NAT.** An office of 20 shares the budget. Raise it, or
  set it to `None` to switch the per-IP budget off entirely.

**A session that was never challenged no longer passes as verified.**
`@mfa_required`, `MfaRequiredMixin`, `@mfa_recent_required`,
`MfaRecentRequiredMixin` and the JSON API now treat a session as pending when
its user holds a primary factor and the session carries no MFA stamp at all.
Previously such a request fell through as though it had passed a challenge,
because `session.is_pending()` means *stamped, but not yet passed* and is False
for a session with no stamp.

The ordinary login path is unaffected for a user who holds a factor when they log
in: `user_logged_in` stamps that session, so it is either pending or verified and
always was. What changes is the sessions that carry no stamp:

- **Sessions opened before their user enrolled.** Login stamps nothing for a user
  with no factor, since there is nothing to challenge yet. Once they enroll, those
  sessions are challenged on decorated views and the API. `MfaMiddleware` only
  started doing the same in 4.6.1 (see below).
- **Your own tests using `force_login()` on a user who holds a factor.** They
  now hit the verify redirect (or `verification_required` on the API) where they
  previously sailed through. Either enroll the factor through the enroll view
  after logging in, or pass the challenge. The testing section of
  {doc}`recipes` shows both, and recommends a user with no factors for tests
  where MFA is incidental.
- **Sessions predating django-mfa's installation.** They are challenged once and
  then behave normally.
- **Cookie-less JSON API clients.** This is the *normal* state of every one of
  their requests, and it is why the change is not optional: without it, an API
  endpoint that requires a verified session would serve a token client that
  was never challenged. See {doc}`rest_api` for the session tokens that fix the
  underlying problem.

## 4.6.1: sessions opened before enrolling are challenged by the middleware

A session opened while its user held no factor carries no MFA stamp, because
login has nothing to challenge yet. `MfaMiddleware` used to let such a session
through even after the user enrolled, so anyone else signed in as that user
before enrollment kept every page the middleware alone protects. It now
redirects that session to `mfa:verify`, the same as a pending one. The session
that completed the enrollment is unaffected, since enrolling verifies it.

What you may notice:

- **Users with other sessions open when they enrolled** are asked for their new
  factor once on each of those sessions.
- **Tests that log in a user, create an `Authenticator` row directly, and then
  request a page protected only by the middleware** now get a redirect to
  `mfa:verify` instead of the page. Enroll through the real enroll view, which
  verifies the session it runs in, or pass the challenge afterwards; the testing
  section of {doc}`recipes` shows both.
- **One extra query per request for users with no factor.** Telling a session
  that was never challenged apart from one whose user has nothing to challenge
  with means asking whether the user holds a factor. Verified sessions are
  decided from the session alone and pay nothing. With `MFA_REQUIRED` on, the
  enrollment wall already asked this question, and the two share one query.
