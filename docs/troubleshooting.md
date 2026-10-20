# Troubleshooting

Find the symptom, then apply the fix under it. `manage.py mfa_status <user>` is a
good first step for any problem with one user: it lists their methods, recovery
codes left, and whether `MFA_REQUIRED` applies to them.

## Setup and startup

### `django_mfa.E001` or `E002` stops `check`, `migrate` or `runserver`

`MFA_FIDO2_RP_ID` is unset (`E001`), or it is not the same as, or a parent domain
of, any entry in `ALLOWED_HOSTS` (`E002`). Set it to your registrable domain:

```python
# settings.py
MFA_FIDO2_RP_ID = "example.com"
ALLOWED_HOSTS = ["example.com", "www.example.com"]
```

For local development use `MFA_FIDO2_RP_ID = "localhost"` with `"localhost"` in
`ALLOWED_HOSTS`. If you do not want passkeys or security keys at all, turn them
off and the checks stop applying (as long as `MFA_QUICKLOGIN` stays off):

```python
# settings.py
MFA_FACTORS = ["totp", "recovery_codes"]
```

### `django_mfa.E003` stops `check`, `migrate` or `runserver`

Passkey login needs its authentication backend. Add it, and keep `ModelBackend`
for password logins:

```python
# settings.py
AUTHENTICATION_BACKENDS = [
    "django_mfa.backends.WebAuthnBackend",
    "django.contrib.auth.backends.ModelBackend",
]
```

### Another `django_mfa.E0xx` error at startup

Each of `E004`–`E011` points at a misconfigured setting. The table in
[System checks](settings.md#system-checks) says which setting and what it expects.

### Users are no longer asked for a second factor after I narrowed `MFA_FACTORS`

Only registered factor types count. A user whose only method was the type you
removed now logs in with a password alone. Their method is still in the database,
so adding the type back to `MFA_FACTORS` protects them again.

Before you remove a type, find the users who would be left without a method and
ask them to enroll another one first:

```python
# python manage.py shell
from django_mfa.models import Authenticator

removing = "totp"                    # the type you plan to drop
keeping = ["webauthn"]               # the primary types you keep
still_covered = Authenticator.objects.filter(type__in=keeping).values("user")
at_risk = (Authenticator.objects.filter(type=removing)
           .exclude(user__in=still_covered)
           .values_list("user__pk", flat=True))
```

Users who were in the middle of logging in when you made the change may see an
empty "Verify it's you" page; see
[The "Verify it's you" page lists no methods](#the-verify-its-you-page-lists-no-methods).

## Redirects and logging out

### Every page redirects to the verify page, and I can't log out

Your logout URL is not in `MFA_EXEMPT_PATHS`, so the logout request is redirected
too. The same applies when every page redirects to the security page because
`MFA_REQUIRED` applies to a user who has not enrolled yet. Add the path exactly as
`request.path` shows it, with the trailing slash:

```python
# settings.py
MFA_EXEMPT_PATHS = ["/accounts/logout/"]
```

### An entry in `MFA_EXEMPT_PATHS` has no effect

Entries match `request.path` exactly. They are not prefixes or patterns, so
`"/api/"` does not cover `/api/orders/`, and `"/logout"` does not match `/logout/`.
List each full path, including the prefix you mounted it under. For a whole
subtree, see
[Your own API endpoints and `MfaMiddleware`](recipes.md#your-own-api-endpoints-and-mfamiddleware).

### The admin's "Log out" link sends me back to the admin

With `MFA_PROTECT_ADMIN = True`, a staff user who has not passed the challenge, or
who holds no factor yet, fails the admin's permission check on every admin page,
including `/admin/logout/`. Django's admin answers that by redirecting to the
admin index instead of logging out.

Log out through your site's own logout URL, outside `/admin/`, and make sure it is
in `MFA_EXEMPT_PATHS` (see [above](#every-page-redirects-to-the-verify-page-and-i-cant-log-out)).

### `/admin/` or an `@mfa_required` view refuses a user who is exempt or in their grace period

Grace periods (`MFA_REQUIRED_FROM`, `MFA_GRACE_PERIOD`) and `manage.py mfa_disable`
only relax `MFA_REQUIRED`. They do not apply to the admin under
`MFA_PROTECT_ADMIN`, or to views behind `@mfa_required` or `MfaRequiredMixin`,
which ask every user for a factor. `mfa_status` describes `MFA_REQUIRED` only, so
it can say "Required: no" for a user the admin still refuses.

The user needs to enroll a method at `/mfa/security/`. See {doc}`enforcement`.

### My own API calls get a 302 to an HTML page

`MfaMiddleware` redirects a session that has not passed its challenge, including
`fetch()` calls from your pages. See
[Your own API endpoints and `MfaMiddleware`](recipes.md#your-own-api-endpoints-and-mfamiddleware)
for a subclass that answers your API paths with a 403 instead.

### A required user is not sent back to the page they asked for after enrolling

This is expected. The redirect to the security page records the original path in
`?next=`, but the built-in enroll and recovery-code pages do not use it. After
enrolling, the user sees their recovery codes, and the "Done" link goes to
`LOGIN_REDIRECT_URL`. Point that setting at a sensible landing page.

### Adding or removing a method asks for a code again

Adding, removing or regenerating a method needs a challenge passed within the last
`MFA_STEPUP_MAX_AGE` seconds (300 by default), not only a verified session. This
also applies to a browser remembered with `MFA_REMEMBER_MY_BROWSER`. The user
passes the challenge and continues. To change the window, see
[Step-up re-authentication](enforcement.md#step-up-re-authentication).

### After enrolling, my other browser asks me for a code

This is expected since 4.6.1. When a user enrolls their first factor, every
session they already had open elsewhere must pass the challenge on its next
request. The session that enrolled is not interrupted. See {doc}`mfa_flow`.

## Passkeys and security keys

### The "Register" or "Use security key" button does nothing

Open the browser console, then check these in order:

1. **Not a secure context.** WebAuthn needs HTTPS. `http://localhost` is allowed;
   `http://192.168.1.10` and other plain-HTTP addresses are not.
2. **Wrong domain.** `MFA_FIDO2_RP_ID` must be the domain in the address bar, or a
   parent of it. In development, open `http://localhost:8000`, not
   `http://127.0.0.1:8000`: an IP address cannot be an RP ID.
3. **A shadowed template.** If you replaced `enroll_webauthn.html` or
   `verify_webauthn.html`, it must keep the element ids `webauthn.js` looks for,
   and render the options with `{% webauthn_options_script %}` rather than
   `json_script`. See {doc}`customizing`.

### The passkey button on my login page shows "Unable to start passkey sign-in."

The script could not fetch the ceremony options. Usually the
`webauthn-passkey-form` element is missing its `data-begin-url` attribute:

```html+django
<form id="webauthn-passkey-form" method="post"
      action="{% url 'mfa:passkey_complete' %}"
      data-begin-url="{% url 'mfa:passkey_begin' %}">
```

See [Adding a passkey button to your login page](recipes.md#adding-a-passkey-button-to-your-login-page)
for the full markup.

### "Your browser does not support WebAuthn" shows on a browser that does

Your CSS is overriding the `hidden` attribute. The browser's own `[hidden]` rule
loses to any class selector that sets `display`, such as a framework's
`.help-block { display: block }`. Add this to your stylesheet:

```css
[hidden] { display: none !important; }
```

### Passkey login works, then the user is anonymous on the next page

`django_mfa.backends.WebAuthnBackend` is missing from `AUTHENTICATION_BACKENDS`.
Django logs the user in, then drops them on the next request because it cannot
find that backend. `django_mfa.E003` reports this at startup; check that it is not
in `SILENCED_SYSTEM_CHECKS`, and add the backend as shown
[above](#django_mfae003-stops-check-migrate-or-runserver).

### Passkey autofill offers nothing

Check, in order:

1. Your username input has `autocomplete="username webauthn"`. Without the
   `webauthn` token the browser has nowhere to show passkeys, and nothing reports
   an error.
2. The passkey form has `data-conditional="true"`.
3. The user has a discoverable passkey for this site. With
   `MFA_FIDO2_RESIDENT_KEY = "discouraged"`, or a security key that stored no
   passkey, there is nothing to offer.
4. The browser console's debug output, where autofill errors are logged with the
   prefix `[django-mfa] passkey autofill:`.

### A passkey login still asks for a second factor

The passkey was unlocked with a touch only (user presence), not a PIN or
biometric, so it counts as one factor. The user can tap the same key again at the
challenge. To refuse presence-only passkey logins instead, set
`MFA_FIDO2_USER_VERIFICATION = "required"`. See
[Passwordless passkey login](mfa_flow.md#passwordless-passkey-login).

### Passkeys work locally but fail in production

`MFA_FIDO2_RP_ID` must be the bare registrable domain: `"example.com"`, not
`"https://example.com"`, and not `"www.example.com"` if users also reach you at
`example.com`. Passkeys registered in development belong to `localhost` and never
work in production.

### Every passkey and security key stopped working after a domain change

Each credential is bound to the `MFA_FIDO2_RP_ID` it was registered under.
Changing that setting breaks all of them, and they cannot be migrated. Set it back
if you can. Otherwise every key has to be registered again. A user who holds
another method, or recovery codes, can sign in with it, remove the old key on the
security page and add it again. A user whose only method was a key is locked out;
see [A user has lost their device](#a-user-has-lost-their-device-and-has-no-recovery-codes).

## Codes and rate limits

### Correct authenticator-app codes are rejected

- **The code was already used.** Each code is accepted once. Wait for the next one.
- **Clock drift.** django-mfa accepts the current code and the ones either side
  (30 seconds each way). Sync the server's clock with NTP, and ask the user to turn
  on automatic time on their phone.
- **Users imported with `mfa_import_django_mfa2`.** That package accepted codes up
  to 15 minutes out of step. A phone clock that far off now fails; fix the clock or
  re-enroll.

### A user's correct code is rejected after a few wrong tries

They hit `MFA_VERIFY_RATE_LIMIT` (5 failures per 5 minutes per method, by
default). A refused attempt shows the same "Your code is expired or invalid."
message as a wrong code, by design. The window starts at the first failure, so the
user can try again within 5 minutes. To clear it now:

```python
# python manage.py shell
from django.contrib.auth import get_user_model
from django_mfa import ratelimit

user = get_user_model().objects.get(username="alice")
ratelimit.clear(user, "totp")  # the method: "totp", "webauthn", "recovery_codes" or "email"
```

### Everyone behind our proxy or office network has their codes rejected

`MFA_VERIFY_IP_RATE_LIMIT` (50 failures per 5 minutes) counts per client address,
and django-mfa reads the address from `REMOTE_ADDR`. Behind a proxy or load
balancer that is the proxy's address, so every user shares one budget. Tell
django-mfa how to find the real address:

```python
# settings.py
MFA_CLIENT_IP_RESOLVER = "myapp.net.client_ip"
```

```python
# myapp/net.py
def client_ip(request):
    # One proxy hop that you control, which appends the client address.
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    return forwarded.rsplit(",", 1)[-1].strip() or None
```

Take the entry your own proxy appended (the last one), never the first, which the
client can set to anything. Adjust for the number of proxies you run. Returning
`None` skips the per-address limit for that request.

### Emailed codes don't arrive

- **Send limit.** A user can be sent `MFA_EMAIL_SEND_RATE_LIMIT` codes (3 per 5
  minutes by default). Past that, no email is sent and the page looks the same.
  Reloading the page reuses the last code while it is still valid
  (`MFA_EMAIL_CODE_VALIDITY`, 5 minutes) rather than sending another.
- **Mail backend failure.** django-mfa logs it at `ERROR` as
  "django_mfa: failed to send a one-time code" (logger `django_mfa.adapters.email`)
  and shows the user nothing different. Check your logs and `EMAIL_BACKEND`.

### Emailed codes go to an old address

Codes go to the address the method was enrolled with, not the user's current
`email` field. To change it, the user removes the emailed-code method on the
security page and enrolls it again.

### Users are challenged at every login despite `MFA_REMEMBER_MY_BROWSER`

- A browser is remembered only after the user passes a challenge page. Enrolling
  and passkey sign-in do not set the cookie.
- Adding or removing any method forgets every remembered browser for that user.
- The cookie is marked `Secure` unless `DEBUG` is on, so it is only kept on HTTPS.
- It expires after `MFA_REMEMBER_DAYS` (90 by default).

## Locked out

### A user has lost their device and has no recovery codes

There is no back door. Verify the user's identity through a channel you trust
first, then remove all their methods:

```bash
python manage.py mfa_reset alice
```

It lists the methods it will remove and asks for confirmation (`--yes` skips the
prompt). The user can then log in with their password alone and enroll again. If
`MFA_REQUIRED` applies to them, they are taken to the security page to do so.

If the user is stuck on the challenge page right now, tell them to log out and log
back in after the reset; see the next entry.

### The "Verify it's you" page lists no methods

The session was marked pending at login, and the user no longer holds any method
that can answer it: an administrator ran `mfa_reset`, or `MFA_FACTORS` was narrowed.
That session cannot recover. The user logs out (your logout URL must be in
`MFA_EXEMPT_PATHS`) and logs back in; the new session is not challenged.

### A user has used up their recovery codes

While they can still log in with another method, they open the security page,
remove "Recovery codes", then click "View recovery codes" to get a new set of ten.
Removing needs a recent challenge, so they may be asked for a code first.

## JSON API

### A cookie-less client loses its verification between requests

Each request without a cookie gets a new, empty session. Mint a session token with
`POST session/` and send it in the `X-MFA-Session` header on every later request.
See {doc}`rest_api`.

### `POST session/` answers 501 `token_sessions_unsupported`

Your `SESSION_ENGINE` is `django.contrib.sessions.backends.signed_cookies`, which
has no server-side session key to hand out. Switch to a server-side engine (the
database, cache or `cached_db` backend) to use tokens.
