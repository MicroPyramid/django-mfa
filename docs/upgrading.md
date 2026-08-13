# Upgrading from django-mfa 2.x/3.x

This release is a ground-up rewrite: U2F support is gone, TOTP and WebAuthn/passkey support are built around a single polymorphic `Authenticator` model instead of one table per factor, and several URLs, session keys, and settings from earlier releases no longer exist. Read this whole page before upgrading a project that has real users with MFA already enabled -- in particular the note on migration `0007` below, which is **irreversible**.

## 1. Django 4.2+ and Python 3.10+ are now required

Earlier releases supported Django 2.2-3.2 and Python 3.6-3.10. This release requires Django 4.2 or 5.2, and Python 3.10-3.13 (see `pyproject.toml`). The old code could not run on a newer Django at all -- it imported `django.utils.http.is_safe_url` and `django.utils.translation.ugettext`, both removed in Django 4.0 -- so there is no supported path that runs both the old and new code against the same Django version; the Django/Python upgrade and the django-mfa upgrade have to happen together.

## 2. U2F support is removed entirely

U2F (the `U2FKey` model, `python-u2flib-server` dependency, and every `u2f`-prefixed view/URL) is gone. There is no migration path for previously registered U2F keys: migration `0007_drop_legacy_models` drops the `U2FKey` table outright, and no prior migration ever copied U2F registrations onto the new `Authenticator` model (unlike TOTP and recovery codes -- see the next section). **Every user whose only second factor was a U2F key loses that factor on upgrade and must re-enroll** with TOTP or a WebAuthn security key/passkey (which is the modern, browser-native successor to U2F and covers the same "physical security key" use case). Warn your users before upgrading if any of them rely on U2F today.

## 3. `UserOTP`, `UserRecoveryCodes`, and `U2FKey` are replaced by `Authenticator`

The three old models are gone from `django_mfa/models.py`. In their place:

- `Authenticator` -- one polymorphic model for every factor type (`type` is `"totp"`, `"webauthn"`, `"recovery_codes"`, or the opt-in `"email"`), factor-specific data in a `data` `JSONField`, and a `user` FK. A user can hold multiple `Authenticator` rows (e.g. several WebAuthn keys), but at most one `totp`, one `recovery_codes`, and one `email` row each (a database constraint enforces this; migration `0008_email_factor` extended it from `totp`/`recovery_codes` to also cover `email` when that factor was added).
- `MfaUserHandle` (`django_mfa/handles.py`) -- a new model, one row per user, holding the stable opaque WebAuthn "user handle" passkey ceremonies use to resolve a user before any password is typed. Created lazily, the first time a user's handle is needed.

Migration `0005_migrate_to_authenticator` copies every existing `UserOTP` row to an `Authenticator` row of type `totp`, and every user's `UserRecoveryCodes` rows to a single `Authenticator` row of type `recovery_codes` holding all of that user's codes together (see item 10 below for what state those codes are in afterwards). Migration `0007` then drops the old tables -- see item 8.

If your project queries `UserOTP`/`UserRecoveryCodes`/`U2FKey` directly (rather than only through django-mfa's own views), that code must be updated to query `Authenticator` instead before upgrading.

## 4. `request.session["verfied_otp"]`/`["verfied_u2f"]` are replaced by `request.session["mfa"]`

The old middleware tracked verification state in two separate, historically **misspelled** session keys, `verfied_otp` and `verfied_u2f` (not "verified"). Both are gone. There is now a single `request.session["mfa"]` dict:

    {"verified": bool, "method": str | None, "at": int | None}

managed entirely through `django_mfa.session` (`start_pending()`, `mark_verified()`, `is_verified()`, `is_pending()`, `reset()`) -- do not read or write `request.session["mfa"]` directly from host-project code; use those functions, since the shape of the dict is not a public contract. If any host-project code inspected the old keys directly (e.g. to customise a template based on MFA status), update it to use `django_mfa.session.is_verified(request)` instead.

## 5. Nine URL names are gone

| Removed name                | Replaced by                                                                                                                                                                              |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `verify_second_factor`      | `mfa:verify` (the factor picker)                                                                                                                                                         |
| `verify_second_factor_totp` | `mfa:verify_factor` with `factor_type="totp"`                                                                                                                                            |
| `verify_second_factor_u2f`  | nothing -- U2F is gone (see item 2)                                                                                                                                                      |
| `u2f_keys`                  | nothing -- U2F is gone                                                                                                                                                                   |
| `add_u2f_key`               | nothing -- U2F is gone                                                                                                                                                                   |
| `configure_mfa`             | `mfa:enroll_factor` with `factor_type="totp"`                                                                                                                                            |
| `enable_mfa`                | `mfa:enroll_factor` (enrolling *is* enabling)                                                                                                                                            |
| `disable_mfa`               | `mfa:manage` (POST, deletes one authenticator)                                                                                                                                           |
| `recovery_codes_download`   | nothing -- download is now built client-side from the codes already in the `mfa:recovery_codes` page (see `recovery_codes.html`); the server never serves plaintext codes a second time. |

`mfa:security_settings` and `mfa:recovery_codes` keep their old names (their URLs/views changed, but not what host projects call them by). Any `{% url %}` tag, hardcoded link, or `reverse()` call in your project referencing a removed name will raise `NoReverseMatch` after upgrading -- search your templates and Python code for the names in the left column above before deploying.

## 6. Host projects no longer set `u2f_pre_verify_user_pk`/`u2f_pre_verify_user_backend`

Under the old U2F contract, a host project's own login view had to stash `request.session['u2f_pre_verify_user_pk']` and `['u2f_pre_verify_user_backend']` by hand *before* calling `django.contrib.auth.login()`, so the (U2F-specific) verify view could rebuild the pending user from those keys. That contract is gone along with U2F itself. A `user_logged_in` signal receiver (`django_mfa.signals.stamp_pending_verification`) now does this automatically for every login, regardless of which view performed it or which authentication backend was used -- **remove any code your login view has that sets those two session keys**; it's dead code that no longer does anything (the new signal doesn't read them), and leaving it in place isn't harmful, just pointless.

## 7. `MFA_FIDO2_RP_ID` is now required for WebAuthn

New setting, required if you want to offer security keys or passkeys at all. There is no sensible default django-mfa could pick on your behalf -- it must be your registrable domain. `manage.py check` (and therefore `migrate`/`runserver`) now refuses to start if it's unset, or set to something that isn't a suffix of any `ALLOWED_HOSTS` entry (checks `django_mfa.E001`/`django_mfa.E002` -- see {doc}`settings`).

:::{warning}
Set this once and do not change it later. WebAuthn credentials are cryptographically bound to the RP ID at registration time; changing it invalidates every previously registered security key and passkey, with no way to migrate them.
:::

## 8. Migration `0007` is irreversible -- roll back from a backup, not `migrate`

`0007_drop_legacy_models` drops the `UserOTP`, `UserRecoveryCodes`, and `U2FKey` tables. It is **deliberately marked irreversible**: running `migrate django_mfa 0006` (or further back) after `0007` has been applied raises `IrreversibleError` and refuses to touch the database.

This is not a technical limitation left unfixed -- it is intentional, and here is why. Django's auto-generated reverse for a dropped table only recreates the table's *schema*; it cannot un-drop the table and bring back the rows that were in it. That looks like a merely cosmetic gap ("the table comes back empty") until you consider the full rollback sequence a `migrate` backwards would perform: unwinding `0007` recreates empty `UserOTP`/`UserRecoveryCodes` tables, and unwinding `0005` right after it *deletes every \`\`Authenticator\`\` row that migration created* (it assumes the original legacy rows it copied from are "still present and untouched" -- true only if `0007` was never applied). The end state: every migrated user's TOTP secret and recovery codes are gone from **both** places at once, and no step in that sequence raises an error -- the operator sees every migration report success. `0007` blocks exactly that sequence from being possible.

**If you need to roll back an upgrade that has already applied migration 0007, the only correct way is to restore a database backup taken before the upgrade ran.** Take that backup *before* running `migrate` as a matter of course for this upgrade specifically -- do not rely on being able to `migrate` your way back out. Once `0007` has run, the pre-migration TOTP secrets and recovery codes exist nowhere else for Django to restore them from.

(U2F registrations were never copied onto `Authenticator` in the first place -- see item 2 -- so they have no forward path regardless of this migration's reversibility. This item is only about the TOTP/recovery-code data that migration `0005` did copy forward.)

## 9. TOTP now tolerates a small clock/window drift

The old TOTP verification used zero tolerance: a code was only accepted in the exact 30-second window the server computed at that instant. This release accepts the previous and next 30-second code as well as the current one (`TOTP_VALID_WINDOW = 1` in `django_mfa/adapters/totp.py`), matching what Google Authenticator, django-otp, and allauth all do. This is strictly more permissive than before -- it fixes spurious rejections from phone clock drift or a user submitting right at a window boundary, and cannot cause a previously-accepted code to be rejected -- so no action is required, but it's worth knowing the acceptance window widened slightly (three times the guess space of a single 6-digit code, which rate limiting, see `MFA_VERIFY_RATE_LIMIT`, already accounts for).

## 10. Recovery codes are hashed at rest -- migrated codes are the exception, until regenerated

Recovery codes generated by this release are hashed at rest (via Django's own password hasher) and, like a password, can never be displayed again once generated -- only shown once, at generation time. Codes carried forward by migration `0005` from a pre-upgrade `UserRecoveryCodes` table are the one exception: they were stored in plaintext under the old schema, and the migration copies them across *as plaintext*, marking that `Authenticator` row with `data["migrated_plaintext"] = True` so verification (`django_mfa/adapters/recovery_codes.py`) knows to compare them directly instead of via the password hasher. **Those specific codes remain plaintext in the database until the user regenerates them** -- simply upgrading does not hash anything that was already stored. There is currently no dedicated "regenerate my recovery codes" affordance in the UI beyond removing the recovery-codes authenticator via `mfa:manage` and revisiting `mfa:recovery_codes` (which then generates a fresh, hashed set); if this matters for your threat model, prompt affected users to do exactly that after upgrading, or run a one-off script that does the same for every user with `data["migrated_plaintext"]` set.

## 11. Passwordless login requires adding `WebAuthnBackend` to `AUTHENTICATION_BACKENDS`

New in this release. If you want users to be able to sign in with a passkey alone (no password, no separate second-factor step), add:

    AUTHENTICATION_BACKENDS = [
        "django_mfa.backends.WebAuthnBackend",
        "django.contrib.auth.backends.ModelBackend",
        # ... any other backends your project already used
    ]

Passwordless login (`mfa:passkey_begin`/`mfa:passkey_complete`) is exposed by `django_mfa.urls` unconditionally -- there is no setting that turns the URLs themselves off. If a user manages to register a WebAuthn credential and this backend is missing, the login *appears* to succeed (`auth.login()` doesn't validate the backend it's given against `AUTHENTICATION_BACKENDS`) and then silently, permanently degrades that session to `AnonymousUser` on the very next request, with no error anywhere. `manage.py check` now catches this at startup (`django_mfa.E003` -- see {doc}`settings`) whenever `MFA_QUICKLOGIN` is on or a WebAuthn adapter is registered (true by default), so a project missing this backend will fail to start rather than fail silently in production.

## 12. Security fixes in 4.0.1 that change observable behaviour

These are fixes to real defects in 4.0.0. All are worth knowing about before you upgrade, but only the last two need any action from you.

- **TOTP codes can now be redeemed only once** (RFC 6238 §5.2). 4.0.0 accepted the same code repeatedly for as long as it stayed inside the ±1 window — roughly 90 seconds. The accepted time step is now recorded in `Authenticator.data["last_verified_counter"]` and any code at or below it is refused. The key appears lazily on first use; no migration is involved. The only user-visible effect is that double-submitting the verification form now fails the second time.

- **New TOTP secrets are 160-bit and come from `secrets`**, not 80-bit values from the `random` module. Existing enrollments are untouched and keep working — an 80-bit secret is still a valid TOTP secret. Users who want the longer secret must re-enroll. Consider prompting them to if your threat model includes an attacker who can observe other output of the same process's `random` module.

- **Recovery-code consumption, TOTP redemption and WebAuthn sign-count updates are now race-free.** All three were read-modify-write on the `data` blob, so two simultaneous requests could lose one another's writes — spending a recovery code twice, or dragging a WebAuthn signature counter backwards and defeating clone detection. They now use a compare-and-set (`django_mfa.atomic.update_data`).

- **The rate-limit window is fixed rather than sliding.** `record_failure()` now uses `cache.add()` + `cache.incr()` so parallel attempts cannot overwrite each other's increments. A side effect is that the window now runs from the first failure instead of being extended by each subsequent one, so a lockout ends slightly sooner than before. **`FileBasedCache` has no atomic `incr()` and must not be used for this** — use redis or memcached.

- **`MFA_REMEMBER_MY_BROWSER` now works for every factor type, and every existing trusted browser is re-challenged once.** The cookie salt used to be derived from the user's TOTP secret, so the feature silently did nothing for users whose only factor was a security key or passkey. It is now derived from the user's whole set of enrolled factors. Because the salt changed, cookies issued by 4.0.0 no longer verify: affected users see one extra second-factor challenge after you deploy, and are then trusted again. Enrolling or removing any factor now also invalidates previously trusted browsers, which it did not reliably do before.

- **`Authenticator` is no longer editable in the Django admin.** It is registered read-only, with add and change disabled and `data` excluded from every field, changelist and search list — a staff account with `view_authenticator` could previously read (and with `change_authenticator`, overwrite) another user's TOTP secret. Deleting is still allowed, so revoking a lost authenticator for a locked-out user still works. **If your project relied on editing `Authenticator` rows through the admin, that will now fail**; register your own `ModelAdmin` if you genuinely need it, and keep `data` out of it.

Separately, the documentation for `MFA_SECRET_ENCRYPTION_KEYS` was wrong: it described the setting as encrypting TOTP secrets at rest. It signs them (`django.core.signing`) and provides integrity only — the payload is plain base64 and recovers without any key. Nothing about the code changed; see {doc}`settings` and {doc}`security` for the corrected description, and re-check any risk assessment that relied on the old wording.
