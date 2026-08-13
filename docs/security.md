# Security model

What django-mfa defends against, how, and — just as important — what it doesn't.

## What it assumes

django-mfa is a **second factor**, not an authentication system. It assumes your
project already authenticates users correctly (password hashing, session security,
CSRF, HTTPS) and adds proof of possession on top. It assumes an attacker may know a
victim's password.

It does not assume your users are careful, that their devices are clean, or that your
login page is the only way into your app.

## Controls

### No account enumeration

Every failure on the passwordless login path returns an identical generic response:
an unknown user handle, an unknown credential, a bad signature, missing or expired
ceremony state, and a tampered payload are indistinguishable to the client. There is
no status-code split, no differing message, and no exception path that would turn one
case into a 500 while others return 400 — that difference would itself be an oracle.

The same holds for second-factor verification: a wrong code, a malformed payload, a
missing field, and a rate-limited attempt all produce the same HTTP 400 and the same
message.

### Rate limiting

Failed attempts are counted per user **per factor type** and capped by
`MFA_VERIFY_RATE_LIMIT` (default `"5/5m"`). A successful verification clears the
counter.

A locked-out attempt returns exactly what a wrong code returns. The lockout is
therefore not observable, and cannot be used to probe whether an account exists or
has MFA enabled.

Two properties worth understanding before you rely on it:

- **The counter lives in Django's cache, with no database fallback.** If the cache is
  empty, flushed, or restarted, attempts are allowed again. This is a deliberate
  availability-over-control trade: a secondary throttle should not be able to lock
  every user out of your site.
- **It is only as shared as your cache is.** With `LocMemCache` and four worker
  processes, each process keeps its own counter, so the effective limit is four times
  what you configured. See the checklist below.

Invalid values are rejected loudly at parse time rather than silently misbehaving: a
count of `0` would lock out every user permanently, and a window of `0` would expire
the counter instantly and disable the throttle. Both raise `ValueError`.

### Cloned-authenticator detection

WebAuthn authenticators may maintain a signature counter that increments on every
assertion. A counter that fails to advance suggests the credential has been copied.
django-mfa checks this on every assertion and refuses the attempt when it regresses.

There's a carve-out: authenticators that never implement a counter always report `0`,
which includes Apple/iCloud passkeys. Treating "not greater than stored" as a clone
would reject every iCloud passkey login. The check distinguishes the two cases — do
not simplify it to `new > stored`.

### Recovery codes

Ten codes, generated together, each usable once. They are hashed with Django's
password hasher, and used codes are marked individually rather than deleted, so a
replay is detected rather than silently accepted.

Plaintext exists only for the duration of the response that displays them. It is
never written to the session, the database, or a log; the download button builds the
file client-side from the codes already on the page, precisely so the server never
has to retain them. Revisiting the page shows nothing — there is nothing left to
show.

**Recovery codes can never be a user's only factor.** They're exhaustible, so
`counts_as_primary_factor = False`: a user holding only recovery codes is offered
them at the picker but is never challenged on their strength alone.

### Secrets at rest

TOTP secrets are stored in plaintext by default and encrypted when
`MFA_SECRET_ENCRYPTION_KEYS` is set — see {doc}`settings` for rotation. WebAuthn
stores only a public key, so there is no secret to protect. Recovery codes are
hashed, not encrypted, because they never need to be read back.

Any comparison between a submitted value and a stored one goes through
`django_mfa.utils.strings_equal`, which normalizes and then uses
`hmac.compare_digest`. There is no `==` on a secret anywhere in the package.

### WebAuthn user handles

The opaque handle a passkey hands back during passwordless login is a **stored random
UUID**, not a signed derivation of the user's primary key.

That distinction is deliberate and load-bearing. Rotating `SECRET_KEY` is routine
security hygiene; passkeys are registered once and used for years. A handle derived
from `SECRET_KEY` would become unresolvable the moment you rotated it — breaking
passwordless login for every user with a passkey, silently, with no sign until they
tried to log in. A stored value survives both key rotation and username changes while
leaking no identity.

### Open redirects

The `next` parameter on verification is validated against the request's host and
scheme before use, falling back to `LOGIN_REDIRECT_URL`. A verification link cannot
be used to bounce a user to an attacker's site.

### Startup checks

Three misconfigurations that would otherwise fail silently in production are `Error`s
at startup rather than warnings — see [System checks](settings.md#system-checks).

## What it does not defend against

Stated plainly, so you can decide what else you need:

- **Real-time phishing / adversary-in-the-middle for TOTP.** A convincing fake login
  page can collect a password and a TOTP code and replay both immediately. This is
  inherent to shared-secret OTP, not specific to this package. **WebAuthn is the
  mitigation** — credentials are bound to the origin, so a passkey cannot be used on
  an attacker's domain. If phishing is in your threat model, prefer passkeys and
  consider not offering TOTP.
- **Compromised sessions.** Once verified, the session is verified. django-mfa does
  not re-challenge for sensitive actions; if you want step-up authentication for,
  say, changing a password, build it on `session.is_verified()` plus your own policy.
- **A compromised server.** TOTP secrets are decryptable by your application by
  definition. Encryption at rest protects against a leaked database dump, not
  against code execution on your host.
- **Malware on the user's device**, SIM swapping (there is no SMS factor — that's
  intentional), or a stolen unlocked phone.
- **Enrollment-time identity.** django-mfa verifies that whoever is logged in
  controls the factor; whether that person should have been logged in is your login
  flow's job.
- **Account recovery policy.** There is no back door. An administrator deleting a
  user's `Authenticator` rows is the recovery path, and verifying identity before
  doing so is on you.

## Production checklist

Before turning this on for real users:

**Configuration**

- [ ] `MFA_EXEMPT_PATHS` includes your logout URL, and you have tested logging out
      from a half-verified session.
- [ ] `MFA_FIDO2_RP_ID` is your registrable domain, set once, and recorded somewhere
      as never-to-be-changed.
- [ ] `manage.py check` is clean, with nothing added to `SILENCED_SYSTEM_CHECKS` that
      you can't justify.
- [ ] `MFA_ISSUER_NAME` is set, so authenticator apps show your product name.

**Infrastructure**

- [ ] **A shared cache backend** (Redis, Memcached) — not `LocMemCache` — or rate
      limiting is per-process and your effective limit is multiplied by your worker
      count.
- [ ] HTTPS everywhere. WebAuthn requires a secure context, and a session cookie
      carrying a verified MFA state deserves `SESSION_COOKIE_SECURE = True`.
- [ ] Server clock synced via NTP. TOTP tolerates one 30-second window either side;
      drift beyond that rejects correct codes.

**Data**

- [ ] Decide about `MFA_SECRET_ENCRYPTION_KEYS`. If you enable it, the keys are in
      your secret store, and you know that existing plaintext secrets are not
      retroactively encrypted.
- [ ] Your database backups are protected at least as well as your password hashes —
      they now contain second-factor material too.

**Process**

- [ ] A documented recovery procedure for a user with no device and no recovery
      codes, including how staff verify identity first.
- [ ] Your support team knows that deleting an `Authenticator` row removes the user's
      second factor entirely.
- [ ] If you plan to narrow `MFA_FACTORS` later, you know it silently de-protects
      users enrolled in the removed factor — see the warning in {doc}`settings`.

## Reporting a vulnerability

Please report security issues privately rather than in a public issue tracker:
[open a security advisory](https://github.com/MicroPyramid/django-mfa/security/advisories/new)
on the repository.
