# Security model

What django-mfa assumes, what each control does, what it leaves to you, and a
checklist to work through before launch.

## What it assumes

django-mfa adds a second factor to a login your project already performs. It
assumes that:

- Your project handles the first factor correctly: password storage, throttling of
  password guesses, and password reset are yours. django-mfa does not rate-limit
  password attempts.
- Django sessions, CSRF protection and HTTPS are configured correctly.
- An attacker may already know a user's password.

It does not assume that users are careful, that their devices are clean, or that
your login page is the only way into your site.

## Controls

### Sessions and enforcement

- **At login.** When a user who holds a primary factor (`totp`, `webauthn` or
  `email`) logs in, their session is marked pending. `MfaMiddleware` redirects
  every request from a pending session to `mfa:verify` until a factor is verified.
- **A pending session is still a logged-in Django session.**
  `request.user.is_authenticated` is `True`. It is kept out only by `MfaMiddleware`,
  the `django_mfa.decorators` decorators and mixins, the admin integration
  (`MFA_PROTECT_ADMIN`) and the JSON API's own checks. Anything outside those, such
  as a view listed in `MFA_EXEMPT_PATHS`, treats the user as logged in.
- **Sessions opened before enrollment are challenged afterwards** (since 4.6.1). A
  session that was never challenged, while its user now holds a primary factor, is
  treated as pending. So after a user enrolls their first factor, every other
  session they had open must pass the challenge. The session that enrolled is
  already verified.
- **What a pending session can reach:** the picker, each factor's verify page, the
  paths in `MFA_EXEMPT_PATHS` (exact match on `request.path`), and the JSON API,
  which applies the same checks itself. It cannot reach the enroll pages, so a
  pending user cannot pass the challenge by enrolling a new factor of their own.
- **Required but not enrolled.** When `MFA_REQUIRED` applies to a user who holds no
  primary factor, the middleware redirects them to `mfa:security_settings`. Only the
  enroll pages, the recovery codes page, the security page and `MFA_EXEMPT_PATHS`
  stay reachable. Without `MFA_REQUIRED`, enrolling is voluntary and a user with no
  factor is never challenged.
- **Recovery codes never count as a primary factor.** They run out. A user holding
  only recovery codes is never challenged and does not satisfy `MFA_REQUIRED`.
- **Verification lasts for the life of the Django session.** Adding or removing a
  factor, or generating recovery codes, also needs a challenge passed within
  `MFA_STEPUP_MAX_AGE` seconds (default 300). See
  [Step-up re-authentication](enforcement.md#step-up-re-authentication).
- **Removing a factor does not end the user's other sessions.** Changing their
  password does, through Django's own session invalidation.
- **Remember this browser** (`MFA_REMEMBER_MY_BROWSER`, off by default). After a
  successful challenge the browser gets a signed `HttpOnly` cookie (`Secure` unless
  `DEBUG`) valid for `MFA_REMEMBER_DAYS` (default 90). The next login on that
  browser skips the challenge. The cookie is bound to the user's current set of
  factors, so adding or removing any factor invalidates it. Anyone holding that
  browser's cookies and the password passes both factors.

### Rate limiting

| Budget | Setting (default) | Counts | Reset by a success |
|---|---|---|---|
| Per user | `MFA_VERIFY_RATE_LIMIT` (`"5/5m"`) | Failed attempts for one user on one factor type | Yes |
| Per client address | `MFA_VERIFY_IP_RATE_LIMIT` (`"50/5m"`) | Failed attempts from one address, across all accounts | No |
| Email sends | `MFA_EMAIL_SEND_RATE_LIMIT` (`"3/5m"`) | Codes emailed to one user | No |

- **A refused attempt looks like a wrong code.** Once either verify budget is
  spent, attempts are refused without being checked and get the same response as a
  wrong code, so the lockout reveals nothing. `mfa_verification_failed` still fires
  for them.
- **Malformed submissions count.** A malformed or incomplete submission is
  recorded as a failure, the same as a wrong code.
- **The window is fixed from the first failure.** Five failures between 12:00:00 and
  12:04:59 lock that budget until 12:05:00.
- **The per-address budget stops guessing across accounts.** An attacker holding
  ten thousand stolen passwords can try one code against each account without
  tripping any per-user budget. A success does not reset the per-address budget, or
  the attacker could reset it by logging into an account of their own.
- **The client address is `REMOTE_ADDR`.** `X-Forwarded-For` is ignored unless
  `MFA_CLIENT_IP_RESOLVER` names a function that reads it, because a client can set
  that header to anything. Behind a proxy or load balancer you must set the
  resolver, or every client shares the proxy's address and one budget. A resolver
  that returns `None` skips the per-address budget for that request;
  `MFA_VERIFY_IP_RATE_LIMIT = None` turns it off entirely.
- **Counters are stored in the database by default** (`RateLimitCounter` rows,
  incremented atomically). With `MFA_RATE_LIMIT_BACKEND = "cache"` they live in
  Django's cache instead: a restart, an eviction or `cache.clear()` resets them, and
  the cache must be shared by every worker and increment atomically. Redis and
  Memcached work. `LocMemCache` (one counter per process) and `FileBasedCache` (not
  atomic) do not.
- **If the store is unreachable, attempts are allowed** and the error is logged
  (`MFA_RATE_LIMIT_FAIL_OPEN = True`). Set it to `False` to refuse verification
  instead, which turns a store outage into a login outage.
- **Enrollment attempts are not counted.** The enrolling user is checking a secret
  they were given moments earlier, not guessing anyone else's.

### Failures look the same

- **Second-factor verification:** a wrong code, a malformed payload, a missing field
  and a rate-limited attempt all return the same HTTP 400 and message, in the HTML
  views and the JSON API.
- **Passwordless login:** an unknown user handle, an unknown credential, a bad
  signature, missing or expired ceremony state, a tampered payload and a regressed
  sign counter all return one identical response. None of them reveals whether an
  account exists.
- **Emailed codes:** a throttled send and a failed delivery look the same as a sent
  code.

### Authenticator app (TOTP)

- **Secrets are 160 bits from `secrets`** (the OS random source), the length RFC 4226
  recommends.
- **Each code works once.** django-mfa stores the time step of the last accepted
  code and refuses any code at or before it (RFC 6238 section 5.2), including when
  two requests race with the same code.
- **The previous and next 30-second codes are accepted** as well as the current one,
  so three codes are valid at any moment. The rate limit covers the wider window.
- **During enrollment the secret goes to the browser** (in the QR code, drawn on your
  server, and in a hidden form field) and comes back with a code. It is saved only
  if the code matches it.

### Security keys and passkeys (WebAuthn)

- **Credentials are bound to your domain.** The `fido2` library checks that every
  ceremony came from an HTTPS origin on `MFA_FIDO2_RP_ID` or a subdomain of it, so a
  passkey cannot be used on a look-alike site.
- **Each challenge works once.** Ceremony state is removed from the session when it
  is used.
- **A credential only verifies for the user it was enrolled to.** Verification
  checks the assertion against that user's own credentials.
- **Cloned authenticators are detected.** Once a credential has reported a non-zero
  signature counter, any assertion that does not increase it is refused.
  Authenticators that always report 0, including Apple/iCloud passkeys, are
  accepted.
- **Passwordless login satisfies both factors only with user verification** (a PIN or
  biometric). An assertion without it logs the user in, but the session stays
  pending until they pass a second factor.
- **Deactivated accounts cannot use a passkey.** A user with `is_active=False` is
  refused at passwordless login with the same response as every other failure, and
  `WebAuthnBackend` ends their existing sessions on the next request, as Django's
  `ModelBackend` does for a password login.
- **User handles are random UUIDs** stored in `MfaUserHandle`. They reveal no
  identity, and rotating `SECRET_KEY` does not break passkeys.
- **Attestation is not verified.** `MFA_FIDO2_ATTESTATION_PREFERENCE` only changes
  what the browser is asked for. django-mfa cannot restrict which authenticator
  models users register.
- **The quick-login cookie identifies an account but authenticates nobody.** With
  `MFA_QUICKLOGIN` on, the browser keeps an `HttpOnly` cookie naming the account it
  last signed into, so your login page can offer that account's passkey. Signing in
  still takes a full WebAuthn ceremony.

### Recovery codes

- **Ten codes, each usable once.** Each is 10 characters from `[A-Za-z0-9]`, drawn
  from `secrets`. Spending a code is atomic, so a replayed or raced code is refused.
- **Hashed with Django's password hasher.** The plaintext exists only in the
  response that displays them; the download button builds its file in the browser.
  Revisiting the page shows nothing.
- **Exception: migrated codes.** Codes copied from the pre-4.0 `UserRecoveryCodes`
  table by migration `0005` stay in plaintext until the user generates a new set.
  See {doc}`upgrading`.

### Emailed codes

The email factor (`"email"` in `MFA_FACTORS`, off by default) is only as strong as
the mailbox it sends to.

:::{warning}
The mailbox is usually also your password-reset channel. Anyone who can read the
user's email can then pass both factors. Offer email as a fallback for users who
have lost their other factors, not as the factor for administrators or anyone with
access to money.
:::

- **Codes go to the address stored at enrollment**, not to whatever `user.email`
  says now. Changing a user's profile address does not move the factor; the user
  removes and re-enrolls it.
- **Codes are short-lived and capped.** A code is valid for `MFA_EMAIL_CODE_VALIDITY`
  seconds (default 300) and is discarded after three wrong guesses. The session
  holds only an HMAC of it, keyed by `SECRET_KEY`.

### Data at rest

| Data | How it is stored |
|---|---|
| TOTP secret | Readable, in `Authenticator.data`. Anyone with the database can generate valid codes. |
| WebAuthn credential | Public key, credential ID and sign counter. Nothing in it lets anyone sign in. |
| Recovery codes | Hashed with Django's password hasher (except migrated codes, above). |
| Email factor | The enrolled address. |
| Rate-limit counters | `RateLimitCounter.scope` holds user IDs and client IP addresses. |
| WebAuthn user handle | A random UUID per user (`MfaUserHandle`). |

:::{warning}
`MFA_SECRET_ENCRYPTION_KEYS` does not encrypt anything. It signs values with
`django.core.signing` under an `mfa1:` prefix, which protects integrity only: the
secret is recoverable from the database without any key. It is deprecated. Treat
the TOTP secret column as plaintext, and protect it with database or disk
encryption and access control.
:::

Submitted codes are compared in constant time, with `django_mfa.utils.strings_equal`
or Django's password hasher.

### Django admin

- **`AuthenticatorAdmin` never shows `Authenticator.data`**: not as a field, a
  column or a search field. That blob holds TOTP secrets, so a staff user who could
  read it could generate codes for anyone, including a superuser.
- **Adding and editing are disabled.** Deleting is allowed, so support staff can
  revoke a lost factor.
- **Deleting in the admin sends no `factor_removed` signal.** Use
  `manage.py mfa_reset` when the removal must reach your audit receivers (see
  {doc}`operations`). If you register your own `ModelAdmin` for `Authenticator`, keep
  `data` out of it.

`MFA_PROTECT_ADMIN = True` makes the default admin site require a verified session
and adds staff users to `MFA_REQUIRED`. See {doc}`enforcement`.

### JSON API

The API is not reachable unless you include `django_mfa.api.urls`. The middleware
lets API requests through; every endpoint applies the same checks itself and
answers with a status code instead of a redirect. Session tokens for cookie-less
clients are server-side session keys, bound to the user they were issued to. CSRF
protection is skipped only for requests that carry no cookies at all. See
{doc}`rest_api`.

### Notifications

`MFA_NOTIFY_ON_CHANGE` (off by default) emails users about changes to their
factors. It is a courtesy, not a control: a failed send is logged at `ERROR` and
dropped. For an audit trail, connect receivers to the signals in {doc}`api`, which
fire whether or not notifications are on.

### Redirects after verification

The `next` parameter is used only when it points at the request's own host (and
over HTTPS when the request was). Anything else falls back to
`LOGIN_REDIRECT_URL`, so a verification link cannot send a user to another site.

### Startup checks

`manage.py check` (and so `migrate` and `runserver`) runs `django_mfa.E001`–`E011`.
All are errors. They catch settings that would otherwise fail silently or on a
user's first request, from WebAuthn configuration to rate-limit specs. See
[System checks](settings.md#system-checks).

## What it does not defend against

- **Real-time phishing of TOTP and emailed codes.** A fake login page can collect a
  password and a code and replay both at once. WebAuthn is the defence: credentials
  are bound to your domain. If phishing is in your threat model, steer users to
  passkeys and consider not offering TOTP or email.
- **A stolen verified session.** Whoever holds the session cookie holds a verified
  session until it ends. django-mfa asks for a fresh challenge only before changing
  factors; protect your own sensitive views with `mfa_recent_required` (see
  [Step-up re-authentication](enforcement.md#step-up-re-authentication)).
- **A leaked database or backup.** TOTP secrets in it are readable and generate
  valid codes. Code execution on your server is worse: it can read anything.
- **Someone who has the password before the user enrolls.** A user's first factor
  is enrolled with only a password login. If an attacker gets there first, they
  enroll their own factor. `MFA_REQUIRED` with a short grace period narrows that
  window; it does not close it.
- **Malware on the user's device, or a stolen unlocked phone** that holds their
  authenticator app or passkeys.
- **Account recovery.** There is no built-in recovery flow. An operator removing a
  user's factors (`manage.py mfa_reset`) is the recovery path, and checking the
  user's identity first is your process.

## Production checklist

Work through this before turning MFA on for real users.

**Configuration**

- [ ] Your logout URL is in `MFA_EXEMPT_PATHS`, written exactly as `request.path`
  sees it (for example `"/accounts/logout/"`). Check it: log in as a user with a
  factor, stop at the challenge, and confirm you can log out.
- [ ] `manage.py check --deploy` shows no `django_mfa` errors, and nothing in
  `SILENCED_SYSTEM_CHECKS` that you cannot justify.
- [ ] `MFA_FIDO2_RP_ID` is your registrable domain, and you have recorded that it
  must never change. Changing it invalidates every registered passkey and key.
- [ ] `MFA_ISSUER_NAME` is set, so authenticator apps show your product's name.
- [ ] You have decided who must enroll (`MFA_REQUIRED`), and set
  `MFA_PROTECT_ADMIN = True` so staff need a second factor to use the admin.
- [ ] `MFA_SECRET_ENCRYPTION_KEYS` is unset on a new install. On an existing install
  that has it set, every key that has signed a stored value is still in the list.
- [ ] If you enable the email factor, you accept that the mailbox becomes a
  credential ([Emailed codes](#emailed-codes)).

**Network**

- [ ] The site is served only over HTTPS, with `SESSION_COOKIE_SECURE = True` and
  `CSRF_COOKIE_SECURE = True`. Browsers refuse WebAuthn outside a secure context.
- [ ] Behind a proxy or load balancer, `MFA_CLIENT_IP_RESOLVER` returns the real
  client address (see {doc}`settings`). Check it on the database backend: after a
  failed attempt, the `scope` of the new `RateLimitCounter` row contains your own
  address, not your proxy's.
- [ ] Server clocks are synchronised with NTP. Drift of more than about 30 seconds
  starts rejecting correct TOTP codes.

**Rate-limit storage**

- [ ] With the default database backend, `manage.py mfa_prune --quiet` runs on a
  schedule (daily is enough, next to `clearsessions`). Expired rows hold client IP
  addresses until it does.
- [ ] With `MFA_RATE_LIMIT_BACKEND = "cache"`, the cache is Redis or Memcached,
  shared by every worker.
- [ ] You have chosen `MFA_RATE_LIMIT_FAIL_OPEN`: allow attempts during a store
  outage (default) or refuse them.

**Data and monitoring**

- [ ] Database access is restricted, and the database and its backups are
  encrypted at rest. Unlike password hashes, the TOTP secrets in them work as soon
  as someone reads them.
- [ ] The `django_mfa` logger reaches your monitoring. Rate-limit store outages and
  failed email deliveries are logged there at `ERROR`.
- [ ] If you need an audit trail, receivers are connected to the signals in
  {doc}`api`.

**Process**

- [ ] There is a written recovery procedure for a user with no device and no
  recovery codes, including how staff verify their identity before running
  `manage.py mfa_reset`.
- [ ] Support staff know that deleting an `Authenticator` row removes that factor
  immediately, and that deleting it in the admin is not reported to signal
  receivers.
- [ ] Anyone who might narrow `MFA_FACTORS` later knows that users enrolled only in
  a removed factor stop being challenged (see {doc}`settings`).

## Reporting a vulnerability

Report security issues privately, not in the public issue tracker:
[open a security advisory](https://github.com/MicroPyramid/django-mfa/security/advisories/new)
on the repository.
