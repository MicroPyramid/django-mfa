# Flow and URLs

Once basic setup (see {doc}`installation_setup`) is done, django-mfa exposes the following URLs under whatever prefix you mounted `django_mfa.urls` at (e.g. `/mfa/`). All names below are reversed with the `mfa:` namespace, e.g. `reverse("mfa:security_settings")`.

| Name                    | Path                    | Purpose                                                                                                         |
|-------------------------|-------------------------|-----------------------------------------------------------------------------------------------------------------|
| `mfa:security_settings` | `security/`             | Overview: enabled factors, factors still available to add, recovery codes remaining.                            |
| `mfa:manage`            | `manage/`               | POST-only: delete one of the user's own authenticators.                                                         |
| `mfa:verify`            | `verify/`               | The second-factor picker (see below).                                                                           |
| `mfa:verify_factor`     | `verify/<factor_type>/` | Challenge screen for one specific factor (`totp`, `webauthn`, or `recovery_codes`).                             |
| `mfa:enroll_factor`     | `enroll/<factor_type>/` | Enrollment screen for one specific factor (`totp` or `webauthn` -- recovery codes are generated, not enrolled). |
| `mfa:recovery_codes`    | `recovery/codes/`       | View (and, on first visit, generate) recovery codes.                                                            |
| `mfa:passkey_begin`     | `passkey/begin/`        | GET: start a passwordless WebAuthn ceremony (see below).                                                        |
| `mfa:passkey_complete`  | `passkey/complete/`     | POST: finish it and log the resolved user in.                                                                   |

`factor_type` is whatever `Authenticator.Type` values are registered -- out of the box, `totp`, `webauthn`, and `recovery_codes`.

## Enrolling a second factor

1.  An already-logged-in user visits `mfa:security_settings`, which lists the factor types they don't yet have (`available_adapters`) as links to `mfa:enroll_factor`.
2.  `GET mfa:enroll_factor/<type>/` renders that factor's enrollment page -- for TOTP, a freshly generated secret and QR code; for WebAuthn, a registration ceremony driven by `django_mfa/static/django_mfa/webauthn.js`.
3.  Completing the ceremony (entering the six-digit code, or a browser completing `navigator.credentials.create()`) POSTs back to the same URL. On success this creates an `Authenticator` row, marks the current session's second factor as satisfied (the user just proved possession), and redirects to `mfa:recovery_codes` if the user has no recovery codes yet, or `mfa:security_settings` otherwise.

## Logging in with a second factor

1.  The host project's own login view authenticates the user as usual (username/password, SSO, etc.) and calls `django.contrib.auth.login()`. A `user_logged_in` signal handler (`django_mfa/signals.py`) then marks the session pending a second factor, if -- and only if -- the user has at least one factor counted as a primary factor (`totp` or `webauthn`; recovery codes alone do not count, since they're exhaustible). This replaces the old contract where a host project's login view had to set session keys by hand.
2.  From that point on, `MfaMiddleware` redirects every request from that session to `mfa:verify` except the picker itself, each registered factor's own verify page, and anything listed in `MFA_EXEMPT_PATHS` (see the warning in {doc}`settings` -- this should include your logout URL).
3.  `mfa:verify` (the picker) looks at which factors this user actually holds. If there's exactly one, it redirects straight to `mfa:verify_factor/<type>/` -- no need to make a user with a single factor choose from a list of one. Otherwise it renders a list to choose from.
4.  `GET mfa:verify_factor/<type>/` renders that factor's challenge screen; POSTing the code/assertion marks the session fully verified on success (or a generic error on failure -- see the rate-limiting note below) and redirects to `next` (validated against open redirects) or `LOGIN_REDIRECT_URL`.

Failed attempts against a single factor are rate-limited (`MFA_VERIFY_RATE_LIMIT`, default 5 per 5 minutes per user per factor type); a locked-out attempt gets the exact same response as a wrong code, so the lockout itself never reveals whether MFA is even enabled for that account.

## Passwordless (passkey) login

A user whose only factor is a WebAuthn passkey doesn't have to go through "password, then second factor" at all -- see {doc}`installation_setup` for the `AUTHENTICATION_BACKENDS` setup this requires.

1.  `GET mfa:passkey_begin` starts a WebAuthn authentication ceremony with an *empty* credential allow-list. That emptiness is what makes the browser prompt offer any discoverable credential it holds for this site, rather than asking for a specific already-known user -- i.e. what makes the login "usernameless".
2.  The browser resolves a credential and its assertion (including the opaque user handle the credential was registered with) is POSTed to `mfa:passkey_complete`. The view resolves the handle back to a user, validates the assertion (reusing the exact same verification code path as `mfa:verify_factor/webauthn/`, including clone detection), and logs the user in via `django_mfa.backends.WebAuthnBackend`.
3.  Whether this satisfies *both* factors in one step depends on whether the assertion carried the WebAuthn User Verification flag (PIN/biometric), not just User Presence:
    - **User-verified** assertion: the session is marked fully verified immediately. A user whose only factor is this same passkey reaches `LOGIN_REDIRECT_URL` directly.
    - **Presence-only** assertion (e.g. a security key with no PIN set up): the user is logged in, but the second factor is left pending exactly as it would be after a plain password login. If that passkey is the user's *only* factor, `MfaMiddleware` sends them to the picker, which sees exactly one factor -- this same passkey -- and redirects straight back to `mfa:verify_factor/webauthn/`, where re-tapping the same key completes the challenge normally. This is deliberate, not a bug: WebAuthn login only strictly requires User Presence, so django-mfa cannot assume User Verification happened without checking.

Every failure mode on the passwordless path -- an unknown handle, an unknown credential, a bad signature, missing/expired ceremony state, a tampered payload -- returns the exact same generic response, so a client can never use timing or response differences to enumerate which accounts exist.

## Removing a factor

`POST mfa:manage` with the authenticator's primary key deletes it (a user may only delete their own). If `MFA_OWNED_BY_ENTERPRISE` is set, WebAuthn authenticators cannot be removed this way -- typically because they represent an organization-issued security key an administrator manages instead of the end user.
