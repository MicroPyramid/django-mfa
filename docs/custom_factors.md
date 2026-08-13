# Writing a custom factor

Adding a factor type means writing one class and registering it. You do not write
views, URLs, or middleware changes — those are generic and dispatch to whatever the
registry holds. The four built-ins (`totp`, `webauthn`, `recovery_codes`, `email`)
are written against exactly the API below; there is no privileged path.

## The shape of it

A factor is a subclass of `django_mfa.registry.Adapter`. It answers four questions:

    from django_mfa.registry import Adapter

    class MyAdapter(Adapter):
        type = "my_factor"              # the URL segment and the DB `type` value
        verbose_name = "My factor"      # shown in the picker and on the security page

        def begin_enroll(self, request): ...
        def complete_enroll(self, request, data): ...
        def begin_verify(self, request, user): ...
        def complete_verify(self, request, user, data): ...

The `begin_*` methods return a dict that is merged into the template context. The
`complete_*` methods receive the POSTed `QueryDict` as `data`.

Once registered, `type` is what appears in `/mfa/enroll/<type>/` and
`/mfa/verify/<type>/`, and what gets stored in `Authenticator.type`.

## A worked example: a printed backup token

A factor django-mfa doesn't ship: one static, hashed backup token, handed to a user
in person or by post, entered once to activate it, and consumed the moment it's used.
Unlike a TOTP secret it never changes and needs no clock sync; unlike ten recovery
codes it's a single value, closer to what an administrator would issue someone who's
lost both their authenticator and their recovery codes. Roughly 40 lines.

    # myapp/mfa.py
    import secrets

    from django.contrib.auth.hashers import check_password, make_password

    from django_mfa.models import Authenticator
    from django_mfa.registry import Adapter

    SESSION_KEY = "myapp_backup_token"


    class BackupTokenAdapter(Adapter):
        type = "backup_token"
        verbose_name = "Backup token"

        # One at a time: once the token is spent, complete_verify() below
        # deletes the row outright, so there's never a second one to hold.
        # (This is the default; shown for clarity — set it True only if
        # several instances make sense, the way several security keys do.)
        supports_multiple = False

        def begin_enroll(self, request):
            # Generated here to keep the example self-contained. Swap this for
            # your own issuing step if you want tokens minted out of band by
            # an administrator and handed to users in person or by post —
            # begin_enroll would then look up an already-issued token instead
            # of minting one, but complete_enroll's job (confirm they have it
            # right) stays the same.
            token = secrets.token_hex(8)
            request.session[SESSION_KEY] = make_password(token)
            return {"token": token}  # shown once: "write this down"

        def complete_enroll(self, request, data):
            # Confirms the user actually recorded the token shown above, the
            # same way TOTP's enrollment confirms a scanned secret rather than
            # trusting that the QR code was read correctly.
            expected_hash = request.session.pop(SESSION_KEY, None)
            if not expected_hash or not check_password(
                    data.get("token", ""), expected_hash):
                raise ValueError("Token did not match.")
            return Authenticator.objects.create(
                user=request.user, type=self.type, data={"hash": expected_hash})

        def begin_verify(self, request, user):
            # Nothing to send: unlike a delivery-based factor, the token was
            # already handed to the user at enrollment, so re-rendering this
            # page on a failed attempt has no side effect to worry about.
            return {}

        def complete_verify(self, request, user, data):
            auth = self.get_instances(user).first()
            if auth is None:
                return False
            if not check_password(data.get("token", ""), auth.data["hash"]):
                return False
            # Single-use: spending it deletes the factor outright rather than
            # marking it used, so a stolen-and-reused token is impossible and
            # re-issuing one (self-service, or through an administrator) is
            # the same complete_enroll() flow as the first time.
            auth.delete()
            return True

Two templates, which can be as short as this:

    {% comment %} myapp/templates/django_mfa/verify_backup_token.html {% endcomment %}
    {% extends base_template %}
    {% block content %}
    <h1>Enter your backup token</h1>
    <form method="post">
      {% csrf_token %}
      <input type="hidden" name="next" value="{{ next }}">
      <input type="text" name="token" autofocus>
      {% if error_message %}<p class="text-danger">{{ error_message }}</p>{% endif %}
      <button type="submit">Verify</button>
    </form>
    {% endblock %}

`enroll_backup_token.html` is the same minus the `next` field, plus showing `{{
token }}` once so the user can copy it down before confirming. See {doc}`customizing`
for the context every page receives.

Then register it once, at startup:

    # myapp/apps.py
    from django.apps import AppConfig

    class MyAppConfig(AppConfig):
        name = "myapp"

        def ready(self):
            from django_mfa.registry import registry
            from myapp.mfa import BackupTokenAdapter
            registry.register(BackupTokenAdapter())

That's the whole integration. The factor now appears on the security page, in the
picker, in the middleware's exempt set, and under rate limiting — none of which you
touched.

For a fuller worked example of a *delivery-based* factor — one with a send step, a
throttle on how often it can be resent, and a masked address shown back to the user —
see the built-in `django_mfa/adapters/email.py`, which this page used to reproduce
here before emailed codes shipped as `"email"` in `MFA_FACTORS`.

## What you get for free

Registering an adapter is enough for all of this:

- **Enroll and verify views**, dispatching on `type`, with `@login_required`.
- **Rate limiting.** `MFA_VERIFY_RATE_LIMIT` applies per user per factor type. You
  do not call it; `verify_factor` does.
- **Uniform failure responses.** Returning `False` and raising `ValueError`,
  `TypeError`, or `KeyError` all produce the same generic HTTP 400. Let a malformed
  payload raise — do not catch it into a distinct message, which would leak more
  than the generic one.
- **Middleware exemption.** `MfaMiddleware` derives its exempt set from
  `registry.all()`, so your verify page is reachable by a pending session
  automatically.
- **Session handling.** The view calls `session.mark_verified()` on success. Do not
  touch `request.session["mfa"]` yourself.
- **Enforcement.** Once a user enrolls, the `user_logged_in` receiver starts
  challenging them.

## The four flags

| Flag | Default | Set it when |
|---|---|---|
| `supports_multiple` | `False` | A user can hold several — WebAuthn does, so someone can register a laptop and a backup key. `is_available()` uses this to decide whether to keep offering the factor. |
| `supports_enroll` | `True` | Set `False` for a factor that is *generated* rather than enrolled. Recovery codes do this; `enroll_factor` then returns 404 for it and the security page never offers it. |
| `counts_as_primary_factor` | `True` | Set `False` for something that must never be a user's only factor. Recovery codes do this — they're exhaustible. It's the difference between "can verify with this" and "is protected by this". |
| `type` / `verbose_name` | — | Always. `verbose_name` is user-visible. |

`counts_as_primary_factor` is the subtle one. `registry.primary_enabled_for()` is the
**single source of truth** for whether to challenge a user, and it filters on this
flag. A factor with it `False` still appears in the picker (you can verify with it)
but never, on its own, causes a challenge — because a user holding only that factor
isn't protected.

## Things to get right

**Raise, don't return, for bad input during enrollment.** `complete_enroll` signals
failure by raising `ValueError`; its return value is the created `Authenticator`.
`complete_verify` signals failure by returning `False`. They are deliberately
different: enrollment has nothing meaningful to return on failure.

**`begin_verify` runs again on failure.** After a wrong code the view re-renders the
challenge page, which means `begin_verify` is called a second time. The worked
example above has no side effect to worry about, but a factor that sends something
(an email, an SMS) on `begin_verify` — see `django_mfa/adapters/email.py` — will send
another one on every wrong-code retry unless you cache the issued value with a TTL
and reuse it, the way `EmailAdapter._ensure_code()` does; decide deliberately.

**Store state in `data`, not in new columns.** `Authenticator.data` is a `JSONField`.
There is no per-factor table and adding one is not the intended extension point.

**Compare secrets with `django_mfa.utils.strings_equal`**, which normalizes and then
uses `hmac.compare_digest`. `==` on a secret is a timing side channel.

**Hash or encrypt anything worth stealing.** `django_mfa.crypto.encrypt`/`decrypt`
give you `MFA_SECRET_ENCRYPTION_KEYS` handling for free — they're a no-op when the
setting is unset, so using them costs nothing and starts working the day someone sets
it. For values you never need to read back, hash instead, as recovery codes do.

## Known rough edges

Being honest about where a custom factor is a slightly second-class citizen:

- **`Authenticator.Type` is a fixed `TextChoices`** with the four built-ins. A row
  with a custom `type` saves and queries fine — Django only validates choices in
  `full_clean()`, which these code paths don't call — but `get_type_display()`
  returns the raw string rather than a label, so `security.html` shows `my_factor`
  instead of `My factor`. Override `security.html` and render
  `adapter.verbose_name` if that matters to you.
- **The singleton database constraint names its types explicitly**
  (`mfa_one_singleton_authenticator_per_user` covers `totp`, `recovery_codes`, and
  `email`). `supports_multiple = False` is enforced in `is_available()` at the
  application level, not by your database, for anything outside that list. For most
  factors that's fine; if you need the guarantee, add your own constraint in a
  migration in your app.
- **`MFA_FACTORS` only controls the built-ins.** Your adapter is registered by your
  own `ready()`, so listing it there does nothing — and an unrecognized name raises
  `ImproperlyConfigured`. Gate registration on your own setting if you need it
  toggleable.
- **`registry.register()` raises `ValueError` on a duplicate `type`.** If your
  `ready()` can run twice (some test setups), guard it or use
  `registry.unregister()` first.

## Testing your factor

The suite in `django_mfa/tests/` uses plain `django.test.TestCase` and `Client`, and
is the best reference. A minimal check that yours is wired up end to end:

    from django.contrib.auth import get_user_model
    from django.test import TestCase
    from django_mfa.registry import registry

    class BackupTokenFactorTests(TestCase):
        def setUp(self):
            self.user = get_user_model().objects.create_user(
                "u", "u@example.com", "pw")
            self.client.force_login(self.user)

        def test_enrolling_protects_the_user(self):
            response = self.client.get("/mfa/enroll/backup_token/")  # issues a token
            token = response.context["token"]
            response = self.client.post(
                "/mfa/enroll/backup_token/", {"token": token})
            self.assertEqual(response.status_code, 302)
            self.assertTrue(registry.primary_enabled_for(self.user))

Assert on `primary_enabled_for()` rather than on "a row exists" — that's the
predicate enforcement actually uses, so it's the one that proves your factor
protects anybody.
