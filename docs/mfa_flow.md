# How it works

This page follows one of your users through django-mfa: setting up a first factor,
logging in with it, signing in with a passkey alone, and removing a factor. Paths
assume you mounted `django_mfa.urls` at `/mfa/`, as in {doc}`installation_setup`.
The [URL table](#urls) at the end lists every page.

## Enrolling a first factor

1. The user opens the security page, `/mfa/security/` (`mfa:security_settings`).
   It lists the methods they hold, the methods they can add, and how many recovery
   codes they have left.
2. They pick a method under "Add a method":
   - **Authenticator app** (`totp`): the page shows a QR code and the secret. They
     scan it and type the six-digit code the app shows.
   - **Security key or passkey** (`webauthn`): the browser asks them to touch the
     key or use Touch ID, Windows Hello or similar. They can give it a name, which
     helps when they hold several.
   - **Emailed code** (`email`, only if you added it to `MFA_FACTORS`): they type
     the code sent to their address.
3. On success the method is saved and the current session counts as verified,
   because the user has proved they hold it.
4. If they have no recovery codes yet, they land on `/mfa/recovery/codes/`, which
   shows ten single-use codes **once**. Otherwise they return to the security page.

Recovery codes are stored hashed and cannot be shown again. For a new set, the
user removes "Recovery codes" on the security page and clicks "View recovery
codes". Recovery codes alone never count as a factor: a user holding only codes is
not challenged at login.

Once a user holds a factor, adding another one needs a recent challenge; see
[Step-up re-authentication](enforcement.md#step-up-re-authentication).

## Logging in with a second factor

```text
login()                         session marked pending (user holds a factor)
   |
   v
GET /account/                   MfaMiddleware redirects
   |
   v
/mfa/verify/?next=/account/     the picker; skipped when there is one method
   |
   v
/mfa/verify/totp/?next=...      the challenge page
   |
   v  correct answer
/account/                       session verified
```

1. Your login view logs the user in as it does today. Anything that ends in
   `django.contrib.auth.login()` works (see {doc}`recipes`). If the user holds a
   factor other than recovery codes, django-mfa marks the session as pending. A
   user with no factor is never challenged.
2. From then on, `MfaMiddleware` redirects every request from that session to
   `/mfa/verify/`, with the page they asked for in `next`. The only pages that stay
   reachable are the picker, each method's challenge page, and the paths in
   `MFA_EXEMPT_PATHS` (which must include your logout URL).
3. The picker, `/mfa/verify/`, lists the methods the user can answer with,
   including recovery codes. If there is exactly one, it skips the list and goes
   straight to that method's challenge page, keeping `next`.
4. When the user answers correctly, the session is verified and they are redirected
   to `next`. A `next` pointing at another host is ignored, and they go to
   `LOGIN_REDIRECT_URL` instead.

Wrong answers are rate limited per user and per client address, and an attempt
refused by the limit gets the same "Your code is expired or invalid." message as a
wrong code; see [Rate limiting](security.md#rate-limiting).

A user who has lost their device chooses "Recovery codes" on the picker and enters
one. A user with no codes left needs your help; see
[A user is locked out](troubleshooting.md#a-user-has-lost-their-device-and-has-no-recovery-codes).

With `MFA_REMEMBER_MY_BROWSER = True`, a browser that passed a challenge skips it on
later logins for `MFA_REMEMBER_DAYS` days. Adding or removing any factor forgets
every remembered browser for that user.

## Sessions that were open before enrolling

When a user enrolls their first factor, every other session they already had open
(another browser, another device, or anyone else signed in as them) is sent to
`/mfa/verify/` on its next request and must pass the challenge. The session they
enrolled from stays verified, so they are not interrupted.

This changed in 4.6.1. Before that, `MfaMiddleware` let those older sessions
through.

## Passwordless passkey login

A user with a passkey can sign in without a username or password. You add a button
(or browser autofill) to your login page; see
[Adding a passkey button to your login page](recipes.md#adding-a-passkey-button-to-your-login-page).

1. The login page fetches `/mfa/passkey/begin/`. The browser then offers any passkey
   it holds for your site; nobody types a username.
2. The browser posts the result to `/mfa/passkey/complete/`, which finds the user the
   passkey belongs to, checks the signature, logs them in, and redirects to `next`
   or `LOGIN_REDIRECT_URL`.
3. What happens next depends on how the user unlocked the passkey:

| The passkey was unlocked with | Result |
|---|---|
| A PIN, fingerprint or face (user verification) | Both factors are satisfied. The user goes straight to `next`. |
| A touch only (user presence), e.g. a security key with no PIN | The user is logged in, but the session is pending, exactly as after a password. They are sent to the challenge and can tap the same key again. |

A touch proves someone holds the key, not who they are, so it counts as one
factor. To refuse presence-only passkey logins, set
`MFA_FIDO2_USER_VERIFICATION = "required"`. Every failure returns the same
response, so the endpoint cannot reveal which accounts exist.

## Being required to enroll

By default nobody has to enroll. When you set `MFA_REQUIRED`, a user it applies to
who holds no factor is redirected to `/mfa/security/` on every request until they
enroll an authenticator app, a security key or passkey, or an emailed code. While
they are held there they can still reach the enroll pages, the recovery codes page
and `MFA_EXEMPT_PATHS`. Generating recovery codes alone does not release them.

After enrolling they see their recovery codes; they are not sent back to the page
they first asked for. See {doc}`enforcement` for the settings and grace periods.

## Removing a factor

The user clicks "Remove" next to a method on the security page. That posts the
method's `pk` to `/mfa/manage/` (`mfa:manage`). Users can only remove their own
methods, and the session needs a recent challenge first; see
[Step-up re-authentication](enforcement.md#step-up-re-authentication).

- With `MFA_OWNED_BY_ENTERPRISE = True`, security keys and passkeys have no Remove
  button and `/mfa/manage/` refuses them with a 403. An administrator removes them
  instead.
- A user who removes their last factor is no longer challenged at login. If
  `MFA_REQUIRED` applies to them, their next request takes them back to the
  security page to enroll again.

## URLs

Paths are relative to where you mounted `django_mfa.urls`. Reverse them with the
`mfa:` namespace, for example `reverse("mfa:security_settings")`.

| Name | Path | Method | Purpose |
|---|---|---|---|
| `mfa:security_settings` | `security/` | GET | The user's methods, what they can add, recovery codes left. |
| `mfa:enroll_factor` | `enroll/<type>/` | GET, POST | Set up `totp`, `webauthn` or `email`. |
| `mfa:recovery_codes` | `recovery/codes/` | GET | Generate recovery codes on the first visit and show them once. |
| `mfa:manage` | `manage/` | POST | Remove one of the user's methods (`pk` in the body). |
| `mfa:verify` | `verify/` | GET | The picker. |
| `mfa:verify_factor` | `verify/<type>/` | GET, POST | Challenge for `totp`, `webauthn`, `recovery_codes` or `email`. |
| `mfa:passkey_begin` | `passkey/begin/` | GET | Start a passwordless login; returns JSON. |
| `mfa:passkey_complete` | `passkey/complete/` | POST | Finish it and log the user in. |

`<type>` must be a factor registered through `MFA_FACTORS`; any other value is a
404. `email` is only available when you add it to `MFA_FACTORS`.
