# django-mfa

:::{div} mfa-lead
Passkeys, security keys and authenticator apps for Django. Add one app, one
middleware and one URL include, and your users have a second factor. Your login
view does not change.
:::

```python
INSTALLED_APPS += ["django_mfa"]
MIDDLEWARE += ["django_mfa.middleware.MfaMiddleware"]
urlpatterns += [path("mfa/", include("django_mfa.urls"))]
```

django-mfa is a finished second-factor feature, not a toolkit. The enrollment
pages, challenge screens, recovery codes, the picker for users with several
methods and the middleware that enforces it are all included, and all of them
can be restyled or replaced. It listens for Django's own `user_logged_in` signal,
so whatever logs your users in today (Django's `LoginView`, django-allauth, SSO)
keeps working.

::::{grid} 1 2 2 3
:gutter: 3

:::{grid-item-card} {octicon}`rocket` Get started
:link: installation_setup
:link-type: doc
:class-card: sd-card-hover

Install the package, wire it into your project and see a second factor working
in about five minutes.
:::

:::{grid-item-card} {octicon}`git-branch` How it works
:link: mfa_flow
:link-type: doc
:class-card: sd-card-hover

What your users go through when they enroll, log in and lose a device, and the
URLs behind each step.
:::

:::{grid-item-card} {octicon}`shield-lock` Require MFA
:link: enforcement
:link-type: doc
:class-card: sd-card-hover

Make a second factor mandatory for everyone, for staff, or for one group, with a
grace period for existing users.
:::

:::{grid-item-card} {octicon}`paintbrush` Customize the screens
:link: customizing
:link-type: doc
:class-card: sd-card-hover

Put the MFA pages inside your own base template, or replace any page outright.
:::

:::{grid-item-card} {octicon}`code` JSON API
:link: rest_api
:link-type: doc
:class-card: sd-card-hover

Every flow as JSON, for a single-page app or a mobile client that draws its own
screens.
:::

:::{grid-item-card} {octicon}`tools` Troubleshooting
:link: troubleshooting
:link-type: doc
:class-card: sd-card-hover

Redirect loops, a passkey button that does nothing, rejected codes, and a user
who is locked out.
:::
::::

## What your users get

| Method | What it is |
|---|---|
| **Passkeys and security keys** | WebAuthn: Touch ID, Windows Hello, Face ID, YubiKey. Works as a second factor, or on its own for passwordless login. |
| **Authenticator apps** | Standard TOTP (RFC 6238), for Google Authenticator, 1Password, Aegis and the rest. The QR code is drawn on your server, so no third party sees a secret. |
| **Recovery codes** | Ten single-use codes, hashed at rest and shown once. They answer "I lost my phone" without a support ticket. |
| **Emailed codes** | Optional. A one-time code sent to the address the user enrolled, as a last-resort fallback. |
| **Remember this browser** | Optional. Skip the challenge on a trusted browser for a number of days. |

A user can hold several of these at once, including several named security keys.
The screens are translated into German, Spanish, French, Brazilian Portuguese,
Japanese and Simplified Chinese.

## Compatibility

| | Supported |
|---|---|
| **Python** | 3.10, 3.11, 3.12, 3.13 |
| **Django** | 4.2 LTS, 5.2 LTS, 6.1 (Django 6.1 needs Python 3.12 or newer) |
| **Database** | Any database Django supports |
| **Dependencies** | `fido2` and `qrcode`. TOTP is built in. |

The source is on [GitHub](https://github.com/MicroPyramid/django-mfa), and
releases are on [PyPI](https://pypi.org/project/django-mfa/).

```{toctree}
:hidden:
:caption: Getting started

installation_setup
mfa_flow
troubleshooting
```

```{toctree}
:hidden:
:caption: Guides

enforcement
customizing
recipes
rest_api
custom_factors
translations
operations
```

```{toctree}
:hidden:
:caption: Reference

settings
api
security
```

```{toctree}
:hidden:
:caption: Project

upgrading
changelog
contributing
```
