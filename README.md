<h1 align="center">django-mfa</h1>

<p align="center">
  <strong>Passkeys, security keys, and authenticator apps for Django.</strong><br>
  Add one app, one middleware, and one URL include — your users get a second factor,<br>
  and you never touch your login view.
</p>

<p align="center">
  <a href="https://pypi.python.org/pypi/django-mfa"><img alt="PyPI" src="https://img.shields.io/pypi/v/django-mfa.svg"></a>
  <a href="https://github.com/MicroPyramid/django-mfa/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/MicroPyramid/django-mfa/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://pypi.python.org/pypi/django-mfa"><img alt="Python versions" src="https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue"></a>
  <a href="https://pypi.python.org/pypi/django-mfa"><img alt="Django versions" src="https://img.shields.io/badge/django-4.2%20%7C%205.2-0C4B33"></a>
  <a href="http://django-mfa.readthedocs.io/en/latest/"><img alt="Docs" src="https://readthedocs.org/projects/django-mfa/badge/?version=latest"></a>
  <a href="https://github.com/MicroPyramid/django-mfa/blob/master/LICENSE"><img alt="License" src="https://img.shields.io/github/license/micropyramid/django-mfa.svg"></a>
</p>

---

Most Django projects get multi-factor authentication as a to-do item that never quite
gets done, because the usual starting point is a low-level framework and a weekend of
writing enrollment views, challenge screens, recovery flows, and rate limiting.

django-mfa is the other end of that trade: a finished second-factor feature you mount
under a URL prefix. Enrollment pages, challenge pages, recovery codes, the picker for
users with more than one method, the middleware that actually enforces it — all
included, all overridable.

```python
INSTALLED_APPS += ["django_mfa"]
MIDDLEWARE += ["django_mfa.middleware.MfaMiddleware"]
urlpatterns += [path("mfa/", include("django_mfa.urls"))]
```

That's a working second factor. Your login view doesn't change — django-mfa listens for
Django's own `user_logged_in` signal.

## What your users get

| | |
|---|---|
| 🔑 **Passkeys & security keys** | WebAuthn/FIDO2 — Touch ID, Windows Hello, Face ID, YubiKey. Usable as a second factor *or* for full passwordless login, with no username typed. |
| 📱 **Authenticator apps** | Standard TOTP (RFC 6238) — Google Authenticator, 1Password, Aegis, anything. QR code rendered server-side as inline SVG; no third-party service ever sees your users' secrets. |
| 🧾 **Recovery codes** | Ten single-use codes, hashed at rest, shown exactly once. The answer to "I lost my phone" that isn't a support ticket. |
| ✉️ **Emailed codes** | Opt-in (`"email"` in `MFA_FACTORS`): a one-time code sent to the address on file, for a user who's lost everything else. Not in the default factor list — an existing install has to opt in. |
| 🖥️ **Remember this browser** | Optional, off by default. Trust a browser for N days after one successful challenge. |
| ➕ **Several keys at once** | A user can register a work laptop's Touch ID *and* a backup YubiKey, each with its own name. |

## Install

```bash
pip install django-mfa      # or: uv add django-mfa
python manage.py migrate
```

> **Upgrading from 2.x or 3.x?** Read the [upgrade notes](https://django-mfa.readthedocs.io/en/latest/upgrading.html)
> first — several changes are breaking, and one migration is deliberately irreversible.

## Quick start

**1. Add the app and the middleware.** The middleware goes *after*
`AuthenticationMiddleware` — it needs `request.user`.

```python
INSTALLED_APPS = [
    ...,
    "django_mfa",
]

MIDDLEWARE = [
    ...,
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_mfa.middleware.MfaMiddleware",
]
```

**2. Mount the URLs** anywhere you like. The `mfa` namespace is baked into the pattern
list, so don't pass `namespace=`:

```python
urlpatterns = [
    ...,
    path("mfa/", include("django_mfa.urls")),
]
```

**3. Exempt your logout URL.** django-mfa can't discover it, and a user who can't
complete their second factor needs a way out:

```python
MFA_EXEMPT_PATHS = ["/logout/"]
```

**4. For passkeys and security keys**, name your relying party and add the backend:

```python
MFA_FIDO2_RP_ID = "example.com"     # set once — changing it invalidates every credential

AUTHENTICATION_BACKENDS = [
    "django_mfa.backends.WebAuthnBackend",
    "django.contrib.auth.backends.ModelBackend",
]
```

Get either of those wrong and `manage.py check` says so at startup, by design — see
[system checks](#it-tells-you-when-youve-misconfigured-it) below. Want TOTP only? Set
`MFA_FACTORS = ["totp", "recovery_codes"]` and skip step 4 entirely; the WebAuthn checks
switch themselves off.

Then send users to `/mfa/security/`. That page lists what they have, what they can add,
and how many recovery codes are left.

## How it fits into your project

**Your login view stays exactly as it is.** Whether you use `django.contrib.auth`'s
built-in view, allauth, or your own SSO handler, all django-mfa needs is that
`login()` gets called. A `user_logged_in` receiver marks the session pending, and the
middleware takes it from there.

**Users without a second factor are never blocked, unless you ask for it.** Someone
with no factor enrolled logs in exactly as before, so you can roll MFA out gradually
instead of on a flag day. Want to *require* it instead — for everyone, for staff, for
one group — set `MFA_REQUIRED`; a required user with no factor is walled to the
security page until they enroll one. See
[Enforcing MFA](http://django-mfa.readthedocs.io/en/latest/enforcement.html).

**The screens are yours.** Every page extends `MFA_BASE_TEMPLATE`, so pointing that at
your own base template is usually all the theming you need. Want more? Shadow any
template under `django_mfa/` in your own app.

| URL | What it is |
|---|---|
| `mfa:security_settings` | Overview — methods enabled, methods available, recovery codes remaining |
| `mfa:enroll_factor` | Enroll a method (TOTP QR code, or a WebAuthn registration ceremony) |
| `mfa:verify` | The picker, shown at login when a user holds more than one method |
| `mfa:verify_factor` | The challenge screen for one method |
| `mfa:recovery_codes` | Generate and display recovery codes |
| `mfa:passkey_begin` / `mfa:passkey_complete` | Passwordless login endpoints |

A user with exactly one method never sees the picker — they're redirected straight to
their challenge.

## Security, in detail

The parts that are easy to get subtly wrong, done deliberately:

- **No account enumeration.** Every failure on the passwordless path — unknown user
  handle, unknown credential, bad signature, expired ceremony, tampered payload —
  returns one identical generic response.
- **Rate limiting that isn't an oracle.** Failed attempts are capped per user per factor
  (`MFA_VERIFY_RATE_LIMIT`, default 5 per 5 minutes). A locked-out attempt returns the
  *same* response as a wrong code, so the lockout itself leaks nothing. The counter
  lives in the cache with no database fallback, so it fails open rather than locking
  everyone out — a secondary control shouldn't be able to take your site down.
- **Cloned-authenticator detection.** WebAuthn signature counters are checked on every
  assertion, with an explicit carve-out for authenticators that legitimately never
  implement one (iCloud passkeys always report 0).
- **Recovery codes are hashed** with Django's password hasher, marked used
  individually, and displayed exactly once.
- **Encryption at rest for TOTP secrets**, opt-in via `MFA_SECRET_ENCRYPTION_KEYS` —
  a *list*, because the first key encrypts and every key is tried on decrypt. That's
  what makes key rotation a redeploy instead of a migration.
- **Recovery codes can never be someone's only factor.** They're exhaustible, so they
  don't count toward "is this user protected" — one source of truth in the registry, not
  a rule re-implemented in three places.
- **Timing-safe comparison** everywhere a submitted code meets a stored one.

### It tells you when you've misconfigured it

Four system checks run on `manage.py check` (and therefore on `migrate` and
`runserver`), because each one guards a failure that is otherwise *silent in
production*:

| Check | Fires when |
|---|---|
| `django_mfa.E001` | `MFA_FIDO2_RP_ID` is unset |
| `django_mfa.E002` | `MFA_FIDO2_RP_ID` doesn't match any `ALLOWED_HOSTS` entry |
| `django_mfa.E003` | `WebAuthnBackend` is missing from `AUTHENTICATION_BACKENDS` |
| `django_mfa.E004` | `MFA_REQUIRED` is a dotted path that fails to import, or resolves to something that isn't callable |

`E003` is the instructive one. Passwordless login calls `login()` with an explicit
`backend=`, which succeeds no matter what `AUTHENTICATION_BACKENDS` says. One request
later, Django re-checks that backend, doesn't find it, and quietly resolves
`request.user` to `AnonymousUser` — no exception, no log line, just a user who was
logged in a moment ago and isn't anymore. Catching that at startup costs nothing;
catching it in production costs a support ticket.

## Adding your own factor

Factors are pluggable. Each one is an `Adapter` subclass registered into a single
registry — the views and URLs are generic and dispatch to whatever's registered, so a
new factor means no new views and no new URLs:

```python
class Adapter:
    def begin_enroll(self, request): ...            # → template context
    def complete_enroll(self, request, data): ...   # ← the POSTed payload
    def begin_verify(self, request, user): ...
    def complete_verify(self, request, user, data): ...
```

Add `enroll_<type>.html` and `verify_<type>.html`, register the adapter, and it appears
in the security page, the picker, and the middleware's exempt set automatically. The
four built-ins (`totp`, `webauthn`, `recovery_codes`, `email`) are written against
this same API — there's no privileged path.

## Compatibility

|  |  |
|---|---|
| **Python** | 3.10 · 3.11 · 3.12 · 3.13 |
| **Django** | 4.2 LTS · 5.2 LTS |
| **Database** | Anything Django supports (state is a `JSONField`) |
| **Dependencies** | `fido2`, `qrcode`. TOTP is implemented in-package, not pulled in. |

Every combination in that grid runs the full suite in CI, along with a job that builds
the wheel, installs it into a clean environment, and starts Django against it from
outside the source tree.

## Documentation

- [Getting started](http://django-mfa.readthedocs.io/en/latest/installation_setup.html) — install and wire it up in five minutes
- [Settings reference](http://django-mfa.readthedocs.io/en/latest/settings.html) — every setting, its default, and what it does
- [Customizing the UI](http://django-mfa.readthedocs.io/en/latest/customizing.html) — templates, context, and the WebAuthn JS contract
- [Enforcing MFA](http://django-mfa.readthedocs.io/en/latest/enforcement.html) — requiring it for some or all users, and per-view enforcement
- [Integration recipes](http://django-mfa.readthedocs.io/en/latest/recipes.html) — allauth, passkey buttons, APIs, testing, troubleshooting
- [Writing a custom factor](http://django-mfa.readthedocs.io/en/latest/custom_factors.html) — the Adapter API, with a worked example
- [Security model](http://django-mfa.readthedocs.io/en/latest/security.html) — controls, non-goals, and a production checklist
- [Flow and URLs](http://django-mfa.readthedocs.io/en/latest/mfa_flow.html) — what happens on enroll, on login, and on passwordless login
- [Upgrade notes](http://django-mfa.readthedocs.io/en/latest/upgrading.html) — read before upgrading a project with real users
- [Contributing](http://django-mfa.readthedocs.io/en/latest/contributing.html)

A runnable demo project lives in [`sandbox/`](sandbox/).

## Contributing

Issues and pull requests are welcome — [open a ticket](https://github.com/MicroPyramid/django-mfa/issues)
for bugs or feature ideas.

```bash
git clone https://github.com/MicroPyramid/django-mfa
cd django-mfa
uv run python test_runner.py     # the whole suite
uv run ruff check .
```

## License

MIT. Built and maintained by [MicroPyramid](https://micropyramid.com/django-development-services/).
