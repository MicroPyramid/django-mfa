# Getting started

## Requirements

|        |                        |
|--------|------------------------|
| Python | 3.10, 3.11, 3.12, 3.13 |
| Django | 4.2, 5.2               |

Any database Django supports works: factor state lives in a `JSONField`, and no
backend-specific features are used.

Upgrading from an older release? See {doc}`upgrading` first — several changes are
breaking, and one migration is irreversible.

## Installation

    pip install django-mfa      # or: uv add django-mfa

:::{warning}
**While 4.0 is in pre-release**, the current PyPI release is 3.2, which predates
WebAuthn and passkeys and does not match this documentation. Install it explicitly
until 4.0 is final:

    pip install --pre django-mfa
:::

## Wiring it up

### 1. Add the app and the middleware

`MfaMiddleware` must come **after** `AuthenticationMiddleware` — it needs
`request.user` to exist.

    INSTALLED_APPS = [
        ...,
        "django_mfa",
    ]

    MIDDLEWARE = [
        ...,
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "django_mfa.middleware.MfaMiddleware",
    ]

### 2. Run migrations

    python manage.py migrate

### 3. Mount the URLs

    urlpatterns = [
        ...,
        path("mfa/", include("django_mfa.urls")),
    ]

`django_mfa.urls` bakes the `mfa` namespace into the pattern list itself — do not
pass `namespace=` to `include()`. Every `reverse()` call inside django-mfa uses the
`mfa:` prefix, so the URL *prefix* you mount it under (`mfa/` above) is entirely
yours to choose.

### 4. Exempt your logout URL

django-mfa has no way to discover it, and a user who cannot complete their second
factor needs a way out:

    MFA_EXEMPT_PATHS = ["/logout/"]

Skip this and a user with a lost device is stuck in a redirect loop they cannot even
log out of. See the warning in {doc}`settings`.

### 5. For security keys and passkeys

Only needed if you want WebAuthn. To offer authenticator apps alone, set
`MFA_FACTORS = ["totp", "recovery_codes"]` and skip this step entirely — the
WebAuthn system checks switch themselves off with it.

    MFA_FIDO2_RP_ID = "example.com"     # your registrable domain

    AUTHENTICATION_BACKENDS = [
        "django_mfa.backends.WebAuthnBackend",
        "django.contrib.auth.backends.ModelBackend",
    ]

:::{warning}
**Set `MFA_FIDO2_RP_ID` once and never change it.** Changing it invalidates every
security key and passkey already registered, with no migration path. See
{doc}`settings` for the full explanation.
:::

Both of these are verified by `manage.py check` (and therefore by `migrate` and
`runserver`) — see [System checks](settings.md#system-checks). If you got either
wrong, you will hear about it at startup rather than from a user.

### 6. Name yourself in authenticator apps

Optional, but users with more than one account will thank you. Without it their app
shows a bare username with no clue which site it belongs to.

    MFA_ISSUER_NAME = "Cool Django App"

## Check that it works

That's the whole setup. Your login view does not change — django-mfa hooks Django's
own `user_logged_in` signal, so whatever authenticates your users today keeps doing
so.

    python manage.py check      # should report no issues

Then, logged in as any user, visit `/mfa/security/`. You should see a page listing
enabled methods (none yet), methods available to add, and recovery codes remaining.
Enroll one, log out, and log back in: you'll be challenged for it.

Users with **no** factor enrolled are never challenged and never blocked, so you can
turn this on for a live site and let people opt in at their own pace.

## Where to go next

- {doc}`mfa_flow` — the URLs this exposes and what happens at each step
- {doc}`customizing` — make the screens look like the rest of your site
- {doc}`recipes` — allauth, custom login views, testing, and troubleshooting
- {doc}`settings` — every setting, its default, and what it does
- {doc}`security` — what django-mfa defends against, and your pre-launch checklist
