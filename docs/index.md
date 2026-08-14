# django-mfa

Second-factor authentication for Django: **authenticator apps (TOTP)**, **security
keys and passkeys (WebAuthn)**, and **recovery codes** — with the enrollment pages,
challenge screens, and enforcement middleware already written.

Add the app, the middleware, and a URL include, and your users have a second factor.
Your login view doesn't change: django-mfa hooks Django's own `user_logged_in`
signal, so whatever authenticates your users today keeps doing so.

    INSTALLED_APPS += ["django_mfa"]
    MIDDLEWARE += ["django_mfa.middleware.MfaMiddleware"]
    urlpatterns += [path("mfa/", include("django_mfa.urls"))]

New here? Start with {doc}`installation_setup`, then skim {doc}`mfa_flow` to see what
your users will actually go through.

Source code: <https://github.com/MicroPyramid/django-mfa>

```{toctree}
:maxdepth: 2
:caption: Getting started

installation_setup
mfa_flow
```

```{toctree}
:maxdepth: 2
:caption: Guides

customizing
translations
enforcement
recipes
custom_factors
operations
```

```{toctree}
:maxdepth: 2
:caption: Reference

settings
api
rest_api
security
```

```{toctree}
:maxdepth: 2
:caption: Project

upgrading
contributing
```
