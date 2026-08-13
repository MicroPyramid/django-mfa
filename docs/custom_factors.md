# Writing a custom factor

Adding a factor type means writing one class and registering it. You do not write
views, URLs, or middleware changes — those are generic and dispatch to whatever the
registry holds. The three built-ins (`totp`, `webauthn`, `recovery_codes`) are
written against exactly the API below; there is no privileged path.

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

## A worked example: email codes

A complete second factor that emails a one-time code. Roughly 40 lines.

    # myapp/mfa.py
    import secrets

    from django.core.mail import send_mail
    from django.utils import timezone

    from django_mfa.models import Authenticator
    from django_mfa.registry import Adapter
    from django_mfa.utils import strings_equal

    SESSION_KEY = "myapp_email_code"


    class EmailAdapter(Adapter):
        type = "email"
        verbose_name = "Emailed code"

        # One enrollment per user: the address lives on the row, and a second
        # row would just be a duplicate. (This is the default; shown for
        # clarity — set it True only if several instances make sense, the way
        # several security keys do.)
        supports_multiple = False

        def _issue(self, user):
            code = f"{secrets.randbelow(1_000_000):06d}"
            send_mail("Your sign-in code", f"Your code is {code}.",
                      None, [user.email])
            return code

        def begin_enroll(self, request):
            request.session[SESSION_KEY] = self._issue(request.user)
            return {"email": request.user.email}

        def complete_enroll(self, request, data):
            expected = request.session.pop(SESSION_KEY, None)
            if not expected or not strings_equal(data["code"], expected):
                raise ValueError("Code did not match.")
            return Authenticator.objects.create(
                user=request.user, type=self.type,
                data={"email": request.user.email})

        def begin_verify(self, request, user):
            request.session[SESSION_KEY] = self._issue(user)
            return {"email": user.email}

        def complete_verify(self, request, user, data):
            expected = request.session.pop(SESSION_KEY, None)
            if not expected or not strings_equal(data.get("code", ""), expected):
                return False
            auth = self.get_instances(user).first()
            if auth is None:
                return False
            auth.record_usage()
            return True

Two templates, which can be as short as this:

    {% comment %} myapp/templates/django_mfa/verify_email.html {% endcomment %}
    {% extends base_template %}
    {% block content %}
    <h1>Check your email</h1>
    <p>We sent a code to {{ email }}.</p>
    <form method="post">
      {% csrf_token %}
      <input type="hidden" name="next" value="{{ next }}">
      <input type="text" name="code" autocomplete="one-time-code" autofocus>
      {% if error_message %}<p class="text-danger">{{ error_message }}</p>{% endif %}
      <button type="submit">Verify</button>
    </form>
    {% endblock %}

`enroll_email.html` is the same minus the `next` field. See {doc}`customizing` for
the context every page receives.

Then register it once, at startup:

    # myapp/apps.py
    from django.apps import AppConfig

    class MyAppConfig(AppConfig):
        name = "myapp"

        def ready(self):
            from django_mfa.registry import registry
            from myapp.mfa import EmailAdapter
            registry.register(EmailAdapter())

That's the whole integration. The factor now appears on the security page, in the
picker, in the middleware's exempt set, and under rate limiting — none of which you
touched.

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
challenge page, which means `begin_verify` is called a second time. If yours has a
side effect — sending an email, as above — every wrong code sends another one. That
may be what you want, or you may want to cache the issued code with a TTL and reuse
it; decide deliberately.

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

- **`Authenticator.Type` is a fixed `TextChoices`** with the three built-ins. A row
  with a custom `type` saves and queries fine — Django only validates choices in
  `full_clean()`, which these code paths don't call — but `get_type_display()`
  returns the raw string rather than a label, so `security.html` shows `my_factor`
  instead of `My factor`. Override `security.html` and render
  `adapter.verbose_name` if that matters to you.
- **The singleton database constraint names its types explicitly**
  (`mfa_one_singleton_authenticator_per_user` covers `totp` and `recovery_codes`).
  `supports_multiple = False` is enforced in `is_available()` at the application
  level, not by your database. For most factors that's fine; if you need the
  guarantee, add your own constraint in a migration in your app.
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

    class EmailFactorTests(TestCase):
        def setUp(self):
            self.user = get_user_model().objects.create_user(
                "u", "u@example.com", "pw")
            self.client.force_login(self.user)

        def test_enrolling_protects_the_user(self):
            self.client.get("/mfa/enroll/email/")           # issues a code
            code = self.client.session["myapp_email_code"]
            response = self.client.post("/mfa/enroll/email/", {"code": code})
            self.assertEqual(response.status_code, 302)
            self.assertTrue(registry.primary_enabled_for(self.user))

Assert on `primary_enabled_for()` rather than on "a row exists" — that's the
predicate enforcement actually uses, so it's the one that proves your factor
protects anybody.
