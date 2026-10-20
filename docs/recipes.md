# Integration recipes

Task-sized answers for wiring django-mfa into your project. If something is not
working, see {doc}`troubleshooting`.

## Using it with your existing login

There is nothing to change. django-mfa listens for Django's `user_logged_in` signal,
so any login that ends in a call to `django.contrib.auth.login()` is already
covered:

- Django's own `LoginView`
- django-allauth, including its social logins
- a custom view that calls `authenticate()` and then `login()`
- SSO and SAML packages that call `login()`
- `Client.login()` and `Client.force_login()` in your tests

A login path that skips `login()` (for example one that writes
`request.session[SESSION_KEY]` itself) sends no signal, so the user is never
challenged. Call `login()`.

Earlier releases asked host projects to set session keys by hand at login. If you
still have that code, delete it; see {doc}`upgrading`.

## Linking users to MFA setup

Link to the security page from your account or profile page:

```html+django
<a href="{% url 'mfa:security_settings' %}">Two-factor authentication</a>
```

That is all an opt-in setup needs. To make MFA mandatory for everyone, for staff or
for a group, see {doc}`enforcement`.

## Checking whether the current session passed MFA

```python
from django_mfa import session

if session.is_verified(request):
    ...
```

Use this rather than reading `request.session["mfa"]`, whose shape is not a public
contract.

`is_verified()` is also `False` for a user who has never enrolled, because there
was nothing to challenge. To tell "not protected" apart from "not verified yet",
also check `registry.has_primary_factor(request.user)` (from
`django_mfa.registry import registry`).

To protect a view rather than branch inside it, use `@mfa_required`; see
{doc}`enforcement`.

django-mfa's own context processor, `django_mfa.context_processors.mfa`, only
exposes `mfa_grace` (see {doc}`enforcement`). To use the verified state in
templates, add a small one of your own:

```python
# myapp/context_processors.py
from django_mfa import session


def mfa_verified(request):
    return {"mfa_verified": session.is_verified(request)}
```

```python
# settings.py
TEMPLATES[0]["OPTIONS"]["context_processors"].append(
    "myapp.context_processors.mfa_verified")
```

## Adding a passkey button to your login page

Lets a returning user sign in with a passkey, without a username or password. The
bundled `webauthn.js` does the work; your page provides the elements it looks for:

```html+django
{# templates/registration/login.html #}
{% load static %}

<div id="webauthn-passkey-unsupported" hidden>
  This browser does not support passkeys.
</div>
<p id="webauthn-passkey-error" role="alert"></p>

<form id="webauthn-passkey-form" method="post"
      action="{% url 'mfa:passkey_complete' %}"
      data-begin-url="{% url 'mfa:passkey_begin' %}">
  {% csrf_token %}
  <input type="hidden" name="next" value="{{ next }}">
  <input type="hidden" name="credential" value="">
  <button type="button" id="webauthn-passkey-start">Sign in with a passkey</button>
</form>

<script src="{% static 'django_mfa/webauthn.js' %}" defer></script>
```

Keep the ids, the `name` attributes and `data-begin-url`: the script finds
everything through them. Without `data-begin-url`, the button only shows "Unable to
start passkey sign-in." The `next` field is optional; a value pointing at another
host is ignored.

It also needs:

- `django_mfa.backends.WebAuthnBackend` in `AUTHENTICATION_BACKENDS`.
  `manage.py check` reports `django_mfa.E003` if it is missing.
- `MFA_FIDO2_RESIDENT_KEY` left at `"preferred"` or set to `"required"`, so that new
  passkeys are discoverable. Only a discoverable passkey can sign in without a
  username.

On success the user is redirected to `next`, or `LOGIN_REDIRECT_URL`. A failed
sign-in answers with HTTP 400 and the JSON body
`{"error": "Passkey sign-in failed."}`, the same for every cause. Whether one tap
satisfies both factors depends on how the passkey was unlocked; see
[Passwordless passkey login](mfa_flow.md#passwordless-passkey-login).

### Offering passkeys in the autofill dropdown

With conditional mediation ("passkey autofill") the browser offers the user's
passkeys in the username field's autofill dropdown, the way it offers saved
passwords. Add `data-conditional="true"` to the passkey form, and the `webauthn`
token to your existing username input:

```html+django
<form id="webauthn-passkey-form" method="post"
      action="{% url 'mfa:passkey_complete' %}"
      data-begin-url="{% url 'mfa:passkey_begin' %}"
      data-conditional="true">
  {% csrf_token %}
  <input type="hidden" name="credential" value="">
  <button type="button" id="webauthn-passkey-start">Sign in with a passkey</button>
</form>

{# your normal login form, anywhere on the same page #}
<input name="username" autocomplete="username webauthn">
```

You need both halves. Without the `autocomplete="username webauthn"` input, the
ceremony starts and nothing is ever offered, with no error anywhere. The input does
not have to be inside the passkey form.

The button keeps working alongside autofill, and a browser without autofill support
gets the button only. Autofill errors go to `console.debug`, not to the page,
because the user did not ask for that prompt.

:::{warning}
Autofill calls `mfa:passkey_begin` on **every view of the login page**, by every
anonymous visitor including bots, and each call writes a challenge to the session.
With database-backed sessions that is one new session row per page view. Make sure
your session store and your `django-admin clearsessions` schedule can take that
before you turn it on for a busy login page.
:::

### Greeting a returning user

With `MFA_QUICKLOGIN = True`, django-mfa sets a cookie at login that remembers
which account last signed in on this browser. Your login page can read it and show
"Sign in as alice" with a passkey prompt before anyone types a username:

```python
# myapp/views.py
from django.shortcuts import render

from django_mfa.quicklogin import COOKIE_NAME, user_from_hint


def login_page(request):
    hinted_user = user_from_hint(request.COOKIES.get(COOKIE_NAME))
    return render(request, "login.html", {"hinted_user": hinted_user})
```

The cookie is a hint, not a credential: it logs nobody in, and the user still
completes a real passkey sign-in. `user_from_hint()` returns `None` for a missing,
stale or tampered cookie and never raises. The cookie is set by `MfaMiddleware` for
every login, whether or not that user has a passkey, and cleared at logout.

Turning `MFA_QUICKLOGIN` on also turns on the passkey system checks
(`django_mfa.E001`–`E003`), even if `"webauthn"` is not in `MFA_FACTORS`.

## Your own API endpoints and `MfaMiddleware`

If you want users to enroll and verify from a mobile app or single-page app, use
{doc}`the JSON API <rest_api>`; `MfaMiddleware` already lets its endpoints through.
This section is about your **own** endpoints.

`MfaMiddleware` answers a pending session with a redirect to `/mfa/verify/`. That
is right for a page and wrong for a `fetch()` call, which gets a 302 to an HTML
page. This only affects endpoints that authenticate with the session cookie. A
request that carries no session cookie and is authenticated inside the view (for
example by Django REST framework's token or JWT authentication) reaches the
middleware as anonymous, so it passes through.

To keep the check but answer API paths with a 403, subclass the middleware:

```python
# myproject/middleware.py
from django.http import JsonResponse

from django_mfa.middleware import MfaMiddleware


class MfaMiddlewareWithApi(MfaMiddleware):
    """Answer API requests with a 403 instead of a redirect."""

    def process_request(self, request):
        response = super().process_request(request)
        if response is not None and request.path.startswith("/api/"):
            return JsonResponse(
                {"error": "mfa_required", "location": response.url}, status=403)
        return response
```

```python
# settings.py
MIDDLEWARE = [
    # ...
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "myproject.middleware.MfaMiddlewareWithApi",  # instead of MfaMiddleware
]
```

A pending session calling `/api/...` now gets
`{"error": "mfa_required", "location": "/mfa/verify/?next=/api/..."}`, and your
client can send the user to `location`.

Avoid exempting the API instead. `MFA_EXEMPT_PATHS` matches `request.path` exactly,
so it cannot cover a whole `/api/` subtree, and a subclass that returns `None` for
those paths lets a session that has not passed its second factor use your API.

## Testing your integration

**Tests where MFA is incidental:** use a user with no enrolled factor. They are
never challenged, so your existing tests need no changes. The exception is a user
`MFA_REQUIRED` applies to, who is redirected to the security page; wrap those
tests in `@override_settings(MFA_REQUIRED=False)`, and add
`MFA_PROTECT_ADMIN=False` if the user is staff.

**Tests of the MFA flow itself:** enroll and verify through the real views, as your
users do. This test enrolls an authenticator app, logs in again, and passes the
challenge:

```python
# myapp/tests.py
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from django_mfa.totp import TOTP  # not public API, but handy in tests


class MfaLoginTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("alice", password="pw")
        self.client.force_login(self.user)

    def enroll_totp(self):
        url = reverse("mfa:enroll_factor", args=["totp"])
        secret = self.client.get(url).context["secret_key"]
        response = self.client.post(
            url, {"secret_key": secret, "code": TOTP(secret).now()})
        self.assertRedirects(response, reverse("mfa:recovery_codes"),
                             fetch_redirect_response=False)
        return secret

    def test_next_login_is_challenged(self):
        secret = self.enroll_totp()
        self.client.logout()
        self.client.force_login(self.user)  # the session is now pending

        response = self.client.get("/account/")
        self.assertRedirects(response, reverse("mfa:verify") + "?next=/account/",
                             fetch_redirect_response=False)

        response = self.client.post(
            reverse("mfa:verify_factor", args=["totp"]),
            {"code": TOTP(secret).now(), "next": "/account/"})
        self.assertRedirects(response, "/account/", fetch_redirect_response=False)
```

Replace `/account/` with any page of yours behind `MfaMiddleware`. A TOTP code is
accepted only once. If one test verifies twice, use the next time step's code for
the second attempt: `TOTP(secret).at(time.time() + 30)`.

To check that a user is protected, assert on
`registry.has_primary_factor(user)` (`from django_mfa.registry import registry`).

For WebAuthn, the package ships an in-process fake authenticator with real keys,
`django_mfa.tests.support.authenticator.SoftwareAuthenticator`, which drives
registration and sign-in without a browser. It is test support rather than public
API, so it may change between releases; `django_mfa/tests/test_passwordless.py`
shows it in use.
