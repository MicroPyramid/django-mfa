# Getting started

This page takes you from installing the package to logging in with a second
factor. It takes about ten minutes, and your login view does not change: django-mfa
listens for Django's `user_logged_in` signal, so whatever logs your users in today
keeps working.

Upgrading an existing install from 2.x or 3.x? Read {doc}`upgrading` first. Several
changes are breaking, and one migration cannot be reversed.

## Requirements

| | Supported |
|---|---|
| Python | 3.10, 3.11, 3.12, 3.13 |
| Django | 4.2, 5.2, 6.1 |
| Database | Any database Django supports |

Django 6.1 needs Python 3.12 or newer. That is Django's requirement, not
django-mfa's: on Python 3.10 or 3.11, use Django 4.2 or 5.2 (both are LTS releases).

Passkeys and security keys only work in a secure context: a page served over HTTPS,
or from `http://localhost`. Authenticator apps work anywhere.

## 1. Install the package

::::{tab-set}
:::{tab-item} pip
```bash
pip install django-mfa
```
:::
:::{tab-item} uv
```bash
uv add django-mfa
```
:::
::::

## 2. Add the app and the middleware

```python
# settings.py
INSTALLED_APPS = [
    # ...
    "django_mfa",
]

MIDDLEWARE = [
    # ...
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_mfa.middleware.MfaMiddleware",  # after AuthenticationMiddleware
]
```

`MfaMiddleware` must come after `AuthenticationMiddleware`, because it reads
`request.user`.

## 3. Create the tables

```bash
python manage.py migrate
```

## 4. Mount the URLs

```python
# urls.py
from django.urls import include, path

urlpatterns = [
    # ...
    path("mfa/", include("django_mfa.urls")),
]
```

The prefix (`mfa/` here) is yours to choose. Do not pass `namespace=` to
`include()`: the `mfa` namespace is already part of `django_mfa.urls`, and every
URL name starts with `mfa:` (for example `reverse("mfa:security_settings")`).

## 5. Let users log out

```python
# settings.py
MFA_EXEMPT_PATHS = ["/logout/"]  # your logout URL, exactly as mounted
```

Once a user holds a second factor, the middleware sends every request from a
session that hasn't passed the challenge to the challenge page. A user who has lost
their device needs one page that still works, and that page is your logout URL.
django-mfa cannot find it on its own.

:::{warning}
Skip this step and a user who cannot complete their second factor is stuck in a
redirect loop that even `/logout/` cannot break. Paths match `request.path`
exactly, so include the trailing slash if your URL has one.
:::

## 6. Choose your factors

Out of the box, users can enroll an authenticator app, a passkey or security key,
and recovery codes. Passkeys need two more settings. If you only want authenticator
apps, switch passkeys off instead.

::::{tab-set}
:::{tab-item} Passkeys and authenticator apps (default)
```python
# settings.py
MFA_FIDO2_RP_ID = "example.com"   # your registrable domain; never change it later
MFA_FIDO2_RP_NAME = "Example"     # your product name, shown by some browsers

AUTHENTICATION_BACKENDS = [
    "django_mfa.backends.WebAuthnBackend",  # needed for passwordless login
    "django.contrib.auth.backends.ModelBackend",
]
```

For local development, use `MFA_FIDO2_RP_ID = "localhost"` and open the site at
`http://localhost:8000`, not `http://127.0.0.1:8000`. A passkey belongs to a
domain name, and an IP address is not one.
:::
:::{tab-item} Authenticator apps only
```python
# settings.py
MFA_FACTORS = ["totp", "recovery_codes"]
```

No `MFA_FIDO2_*` settings and no extra authentication backend are needed. The
passkey checks described below switch themselves off.
:::
::::

:::{warning}
**Set `MFA_FIDO2_RP_ID` once and never change it.** Every passkey and security key
is bound to it when it is registered. Changing it later makes all of them stop
working, and the only fix is for each user to remove and re-register theirs. See
{doc}`settings`.
:::

You don't have to remember these rules: `manage.py check` (which `migrate` and
`runserver` also run) fails with `django_mfa.E001`, `E002` or `E003` when
`MFA_FIDO2_RP_ID` is missing, doesn't match `ALLOWED_HOSTS`, or the backend is
missing. See [System checks](settings.md#system-checks).

Emailed one-time codes are a fourth, optional factor. They are off by default; see
{doc}`settings` to turn them on.

## 7. Name your site in authenticator apps

```python
# settings.py
MFA_ISSUER_NAME = "Example"
```

This label appears next to the username in the user's authenticator app. Without
it, someone with accounts on several sites sees a bare username and has to guess
which site the code is for.

## 8. Link to the security page

Users manage their methods at `mfa:security_settings`. Link to it from your account
or profile page:

```html+django
<a href="{% url 'mfa:security_settings' %}">Two-factor authentication</a>
```

## Check that it works

1. Run the system checks. They should report no issues:

   ```bash
   python manage.py check
   ```

2. Start the server, log in as any user and open `/mfa/security/`. You should see
   your enabled methods (none yet), the methods you can add, and the number of
   recovery codes left.
3. Add an authenticator app: scan the QR code, then type the six-digit code it
   shows. django-mfa then shows ten recovery codes, once. Save them.
4. Log out and log in again. After your password, you are asked for a code from the
   app. Enter it and you land where you were going.

Users who have not enrolled a factor are never challenged or blocked, so you can
deploy this to a live site and let people opt in at their own pace. To make MFA
mandatory for some or all users, see {doc}`enforcement`.

## All the settings from this page

```python
# settings.py
INSTALLED_APPS = [
    # ...
    "django_mfa",
]

MIDDLEWARE = [
    # ...
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_mfa.middleware.MfaMiddleware",
]

AUTHENTICATION_BACKENDS = [
    "django_mfa.backends.WebAuthnBackend",
    "django.contrib.auth.backends.ModelBackend",
]

MFA_EXEMPT_PATHS = ["/logout/"]
MFA_ISSUER_NAME = "Example"
MFA_FIDO2_RP_ID = "example.com"
MFA_FIDO2_RP_NAME = "Example"
```

## Try the demo project

The repository includes a small demo project in `sandbox/`, already wired up with
passkeys enabled for `localhost`. From a clone of the repository:

```bash
git clone https://github.com/MicroPyramid/django-mfa
cd django-mfa/sandbox
uv run --project .. python manage.py migrate
uv run --project .. python manage.py runserver
```

Open `http://localhost:8000`, register an account, and visit
`http://localhost:8000/settings/security/` (the demo mounts django-mfa under
`settings/`).

## Next steps

- {doc}`mfa_flow`: what your users see at each step, and the URLs behind it.
- {doc}`enforcement`: require a second factor for everyone, for staff, or for a
  group.
- {doc}`customizing`: make the screens match the rest of your site.
- {doc}`recipes`: allauth, a passkey button on your login page, and tests.
- {doc}`security`: what django-mfa protects against, and a checklist to work
  through before launch.
