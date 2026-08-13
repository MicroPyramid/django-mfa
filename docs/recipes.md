# Integration recipes

Common things host projects need to do, and the failure modes people hit first.

## Using it with your existing login

**There is nothing to do.** django-mfa hooks `django.contrib.auth.signals.user_logged_in`,
so anything that ends in a call to `django.contrib.auth.login()` is already
integrated:

- Django's own `LoginView`
- `django-allauth` (including its social logins)
- A custom view calling `authenticate()` then `login()`
- SSO and SAML packages that call `login()`
- `Client.force_login()` in your tests

If your login path does **not** call `login()` — a hand-rolled view that sets
`request.session[SESSION_KEY]` directly, for instance — no signal fires and no
challenge happens. Call `login()`; that's the contract.

Earlier releases required host projects to set session keys by hand. If you still
have that code, delete it — see {doc}`upgrading`.

## Sending people to set up MFA

Whether MFA is mandatory, and for whom, is a policy decision — `MFA_REQUIRED`
answers it. See {doc}`enforcement` for the full reference: the four shapes the
setting takes (`True`, a predicate, `is_staff`, `in_groups(...)`), what a
required-but-unenrolled user can still reach before locking themselves out, and
`@mfa_required`/`MfaRequiredMixin` for requiring it per view instead of per user.
That page also covers `MFA_EXEMPT_PATHS`, which the enrollment wall needs the same
way the pending-verification wall does — skip it and you build a redirect loop.

For MFA that's entirely opt-in (the default, and still the right choice for most
projects), just point users at the settings page from your account area:

    <a href="{% url 'mfa:security_settings' %}">Two-factor authentication</a>

## Checking whether the current session passed MFA

    from django_mfa import session

    if session.is_verified(request):
        ...

Use these helpers rather than reading `request.session["mfa"]`. The dict's shape is
not a public contract and has changed once already.

For a template, pass it through your own context processor — django-mfa doesn't
install one.

## Adding a passkey button to your login page

Lets a returning user sign in with Touch ID or a security key without typing
anything. Two endpoints do the work: `mfa:passkey_begin` (GET, returns ceremony
options as JSON) and `mfa:passkey_complete` (POST).

The bundled `webauthn.js` already drives this if you give it the elements it looks
for by ID:

    {% load static %}

    <div id="webauthn-passkey-unsupported" hidden>
      This browser doesn't support passkeys.
    </div>
    <p id="webauthn-passkey-error"></p>

    <form id="webauthn-passkey-form" method="post"
          action="{% url 'mfa:passkey_complete' %}">
      {% csrf_token %}
      <input type="hidden" name="credential" value="">
      <button type="button" id="webauthn-passkey-start">Sign in with a passkey</button>
    </form>

    <script src="{% static 'django_mfa/webauthn.js' %}" defer></script>

This requires `django_mfa.backends.WebAuthnBackend` in `AUTHENTICATION_BACKENDS` —
`django_mfa.E003` will tell you at startup if it's missing, because the failure is
otherwise silent. It also requires discoverable credentials, so leave
`MFA_FIDO2_RESIDENT_KEY` at `"preferred"` or set it to `"required"`.

Whether one passkey tap satisfies *both* factors depends on user verification (PIN or
biometric) rather than mere presence — see {doc}`mfa_flow`.

### Greeting a returning user by name

With `MFA_QUICKLOGIN = True`, django-mfa sets a hint cookie naming the last account
to log in on this browser, so your login page can show "Sign in as Ashwin" before any
username is typed:

    from django_mfa.quicklogin import COOKIE_NAME, user_from_hint

    def login_page(request):
        hinted = user_from_hint(request.COOKIES.get(COOKIE_NAME))
        return render(request, "login.html", {"hinted_user": hinted})

The cookie is a **hint, not a credential**. It never authenticates anyone; the user
still completes a real WebAuthn ceremony. `user_from_hint()` never raises — a
missing, stale, or tampered cookie returns `None`.

## APIs and non-browser clients

`MfaMiddleware` responds to a pending session with a **redirect**, which is right for
a browser and wrong for an API client — a mobile app or `fetch()` caller sees a 302
to an HTML page instead of a useful error.

If your API sits under a path prefix and authenticates with tokens rather than
session cookies, the simplest fix is to exempt it, since token auth doesn't go
through the session at all:

    MFA_EXEMPT_PATHS = ["/logout/"]     # plus your API's paths if session-authed

Note that `MFA_EXEMPT_PATHS` matches `request.path` **exactly** — it is not a prefix
match. For a whole API subtree, wrap the middleware instead:

    class MfaMiddlewareExceptApi(MfaMiddleware):
        def process_request(self, request):
            if request.path.startswith("/api/"):
                return None
            return super().process_request(request)

Exempting a session-authenticated API means a half-verified session can reach it.
That's a real trade-off, not a formality — make it deliberately.

## Testing your integration

The package's own tests are plain `django.test.TestCase` and `Client`; yours can be
too.

Enrolling TOTP without a phone:

    from django_mfa import totp
    from django_mfa.adapters.totp import generate_secret

    secret = generate_secret()
    response = self.client.post("/mfa/enroll/totp/", {
        "secret_key": secret,
        "code": totp.TOTP(secret).now(),
    })

Passing the challenge later uses the same `.now()` against `/mfa/verify/totp/`.

Asserting that a user is actually protected:

    from django_mfa.registry import registry
    self.assertTrue(registry.primary_enabled_for(user))

**For tests of other features, where MFA is incidental, use a user with no enrolled
factors.** They are never stamped pending and never challenged, so nothing about your
existing tests needs to change. Reach for a real enroll-and-verify round trip only
when the test is about MFA itself — that exercises the same code path your users do,
and doesn't depend on the session dict's shape.

For WebAuthn, don't hand-build fixtures. `django_mfa/tests/support/authenticator.py`
provides `SoftwareAuthenticator`, an in-process fake authenticator with real
EC P-256 keys and real `fido2` ceremony objects, which drives registration and
authentication end to end without a browser.

## Troubleshooting

**Every request redirects to the verify page, and I can't even log out.**
Your logout URL isn't in `MFA_EXEMPT_PATHS`. Add it. Matching is exact, so include
the trailing slash exactly as mounted.

**`django_mfa.E001` / `E002` at startup.**
`MFA_FIDO2_RP_ID` is unset, or isn't a suffix of any `ALLOWED_HOSTS` entry. For local
development that usually means `MFA_FIDO2_RP_ID = "localhost"` and `"localhost"` in
`ALLOWED_HOSTS`. If you don't want WebAuthn at all, set
`MFA_FACTORS = ["totp", "recovery_codes"]` and the checks stop applying.

**`django_mfa.E003` at startup.**
Add `django_mfa.backends.WebAuthnBackend` to `AUTHENTICATION_BACKENDS`, keeping
`ModelBackend` for password login.

**The "register security key" button does nothing.**
Three usual causes: the page isn't served over HTTPS (WebAuthn requires a secure
context — `http://localhost` is exempt, `http://192.168.x.x` is not);
`MFA_FIDO2_RP_ID` doesn't match the domain in the address bar; or you overrode the
template and dropped one of the element IDs `webauthn.js` needs. See
{doc}`customizing`.

**"Your browser does not support WebAuthn" on a browser that clearly does.**
Your CSS is overriding the `hidden` attribute. The UA rule `[hidden] {display:none}`
loses to any class selector that sets `display`, so a framework's
`.help-block {display:block}` wins. Add `[hidden] { display: none !important; }`.

**Passkey login works, then the user is anonymous on the next request.**
`WebAuthnBackend` is missing from `AUTHENTICATION_BACKENDS`. This is exactly what
`E003` catches — check you haven't silenced it.

**Users report their TOTP codes are rejected.**
Server clock drift. django-mfa accepts the previous and next 30-second window
already; beyond that, fix NTP on the server.

**A user is locked out with no recovery codes.**
There is no back door by design. Delete their `Authenticator` rows — from the Django
admin, or:

    from django_mfa.models import Authenticator
    Authenticator.objects.filter(user=user).delete()

They can then log in with their password alone and re-enroll. Verify identity out of
band first; this removes their second factor entirely.

**Everything works locally and fails in production.**
Almost always `MFA_FIDO2_RP_ID`: it must be the registrable domain, not the full
origin. `"example.com"` — not `"https://example.com"`, not `"www.example.com"` if
users reach you at both.
