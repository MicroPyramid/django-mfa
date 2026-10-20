# Writing a custom factor

A new factor type is one class, two templates and one call to register it. You do
not write views, URLs or middleware changes: the enroll and verify views, the
security page, the picker and the JSON API all work from whatever factors are
registered. The built-in factors (`totp`, `webauthn`, `recovery_codes`, `email`)
use the same API.

## A worked example: a backup token

This factor is a single static token. The user writes it down when they set it
up, and it works once. It is a spare way in for someone who already has another
method, much like a single recovery code.

### 1. The adapter

```python
# myapp/mfa.py
import secrets

from django.contrib.auth.hashers import check_password, make_password
from django.utils.translation import gettext_lazy as _

from django_mfa.models import Authenticator
from django_mfa.registry import Adapter

SESSION_KEY = "myapp_backup_token"


class BackupTokenAdapter(Adapter):
    type = "backup_token"
    verbose_name = _("Backup token")
    # Single-use, so it must never be someone's only factor.
    counts_as_primary_factor = False

    def begin_enroll(self, request):
        token = secrets.token_hex(8)
        request.session[SESSION_KEY] = make_password(token)
        return {"token": token}

    def complete_enroll(self, request, data):
        expected = request.session.pop(SESSION_KEY, None)
        if self.get_instances(request.user).exists():
            raise ValueError("This user already holds a backup token.")
        if not expected or not check_password(data.get("token", ""), expected):
            raise ValueError("Token did not match.")
        return Authenticator.objects.create(
            user=request.user, type=self.type, data={"hash": expected})

    def begin_verify(self, request, user):
        return {}

    def complete_verify(self, request, user, data):
        authenticator = self.get_instances(user).first()
        if authenticator is None:
            return False
        if not check_password(data.get("token", ""), authenticator.data["hash"]):
            return False
        # Spend it. Of two requests racing with the same token, only one
        # deletes the row, so only one succeeds.
        deleted = Authenticator.objects.filter(pk=authenticator.pk).delete()[0]
        return deleted == 1
```

`begin_enroll` shows the token once and keeps only its hash in the session.
`complete_enroll` makes the user type it back, the way TOTP setup asks for a code
before saving the secret. Only the hash is stored.

### 2. The templates

Enroll and verify pages are found by type: `django_mfa/enroll_<type>.html` and
`django_mfa/verify_<type>.html`. Each receives the dict its `begin_*` method
returned, plus the context every such page gets (`base_template`, `adapter`,
`error_message`, and `next` on verify pages; see
[Template context](customizing.md#template-context)).

```html+django
{# myapp/templates/django_mfa/enroll_backup_token.html #}
{% extends base_template %}
{% block content %}
<section class="mfa-card">
  <h1>Your backup token</h1>
  <p>Write it down now. It works once and is not shown again.</p>
  <p><code>{{ token }}</code></p>
  <form method="post">
    {% csrf_token %}
    <label for="id_token">Type it back to confirm</label>
    <input class="form-control" id="id_token" type="text" name="token" autocomplete="off" required>
    {% if error_message %}<p class="text-danger">{{ error_message }}</p>{% endif %}
    <div class="mfa-actions">
      <button type="submit" class="btn btn-primary">Save</button>
    </div>
  </form>
</section>
{% endblock %}
```

```html+django
{# myapp/templates/django_mfa/verify_backup_token.html #}
{% extends base_template %}
{% block content %}
<section class="mfa-card">
  <h1>Enter your backup token</h1>
  <form method="post">
    {% csrf_token %}
    <input type="hidden" name="next" value="{{ next }}">
    <input class="form-control" type="text" name="token" autocomplete="off" autofocus required>
    {% if error_message %}<p class="text-danger">{{ error_message }}</p>{% endif %}
    <div class="mfa-actions">
      <button type="submit" class="btn btn-primary">Verify</button>
      <a href="{% url 'mfa:verify' %}" class="btn btn-default">Use another method</a>
    </div>
  </form>
</section>
{% endblock %}
```

### 3. Register it

```python
# myapp/apps.py
from django.apps import AppConfig


class MyAppConfig(AppConfig):
    name = "myapp"

    def ready(self):
        from django_mfa.registry import registry

        from myapp.mfa import BackupTokenAdapter

        registry.register(BackupTokenAdapter())
```

Order in `INSTALLED_APPS` does not matter. Open the security page and "Backup
token" should appear under "Add a method".

### 4. Test it

```python
# myapp/tests.py
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from django_mfa.models import Authenticator


class BackupTokenTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("ana", password="pw")
        self.client.force_login(self.user)

    def test_enroll_then_spend(self):
        enroll = reverse("mfa:enroll_factor", args=["backup_token"])
        token = self.client.get(enroll).context["token"]
        self.assertEqual(self.client.post(enroll, {"token": token}).status_code, 302)

        verify = reverse("mfa:verify_factor", args=["backup_token"])
        self.assertEqual(self.client.post(verify, {"token": "wrong"}).status_code, 400)
        self.assertEqual(self.client.post(verify, {"token": token}).status_code, 302)

        # Spent: the row is gone and the same token no longer works.
        self.assertFalse(Authenticator.objects.filter(type="backup_token").exists())
        self.assertEqual(self.client.post(verify, {"token": token}).status_code, 400)
```

For a factor that sends something (a code by email or SMS), read the built-in
`django_mfa/adapters/email.py`. It shows the send step, a limit on resends and a
masked address.

## What you get without writing it

- **Pages** at `mfa:enroll_factor` and `mfa:verify_factor`, with `type` as the
  URL argument. Both need a logged-in user. Enrolling also needs a recent
  challenge when the user already holds a factor other than recovery codes (see
  [Step-up re-authentication](enforcement.md#step-up-re-authentication)).
- **The security page and the picker**: offered under "Add a method", listed with
  a remove button once held, offered at login.
- **Rate limiting** of failed verifications, by `MFA_VERIFY_RATE_LIMIT` and
  `MFA_VERIFY_IP_RATE_LIMIT`.
- **Uniform failures**: every rejected attempt gets the same message and HTTP 400.
- **Middleware access**: a session waiting for its challenge can reach the verify
  page, and a user held by `MFA_REQUIRED` can reach the enroll page.
- **Session state and signals**: success marks the session verified and sends
  `factor_added` (with the `Authenticator` you returned) or `mfa_verified`;
  failure sends `mfa_verification_failed`; removal sends `factor_removed`. With
  `MFA_NOTIFY_ON_CHANGE` on, the user gets the usual emails.
- **The JSON API**, if mounted, through its enroll and verify endpoints. See
  {doc}`rest_api`.
- **Enforcement**, if `counts_as_primary_factor` is true: a user who holds the
  factor is challenged at login and satisfies `MFA_REQUIRED`.

## The `Adapter` API

Subclass `django_mfa.registry.Adapter`.

### Attributes

| Attribute | Default | Meaning |
|---|---|---|
| `type` | `None` | Required. The URL segment, the `Authenticator.type` value and the template suffix. Use lowercase letters, digits and underscores, at most 32 characters, and not a built-in name. |
| `verbose_name` | `None` | Required. The name users see in the picker and under "Add a method". Wrap it in `gettext_lazy` if your site is translated. |
| `supports_multiple` | `False` | Whether a user may hold several, as with security keys. When `False`, the factor stops being offered under "Add a method" once the user holds one. That is all it does; see [Known limitations](#known-limitations). |
| `supports_enroll` | `True` | Set `False` for a factor that is created some other way, as recovery codes are generated on their own page. The enroll page then returns 404 and the factor is never offered under "Add a method". You do not need `begin_enroll`, `complete_enroll` or an enroll template. |
| `counts_as_primary_factor` | `True` | Whether holding this factor protects the user on its own. Set `False` for anything that can run out, as recovery codes and the example above do. Such a factor is still offered at login, but a user holding only it is never challenged and does not satisfy `MFA_REQUIRED`. |

### Methods

| Method | Return | Called |
|---|---|---|
| `begin_enroll(request)` | A dict, merged into the enroll page's context | Every time the enroll page is shown, including after a failed attempt |
| `complete_enroll(request, data)` | The new `Authenticator` row | On submit. Raise `ValueError` to reject. |
| `begin_verify(request, user)` | A dict, merged into the verify page's context | Every time the verify page is shown, including after a failed attempt |
| `complete_verify(request, user, data)` | `True` or `False` | On submit. |
| `is_available(user)` | `bool` | To decide whether to offer the factor under "Add a method". Override it to add a condition; the email factor hides itself from accounts with no email address. Call `super()` to keep the `supports_multiple` check. |

The base class also gives you `get_instances(user)` (this user's rows of this
type, as a queryset) and `is_enabled(user)`. The `enroll_template` and
`verify_template` properties return the template names above; override them to
use other names.

`data` is `request.POST` for the HTML pages, or the decoded JSON object for the
JSON API. Read it with `data.get(...)`. For the same reason, anything `begin_*`
returns must be JSON-serialisable if the JSON API is mounted.

### Rejecting an attempt

- In `complete_enroll`, raise `ValueError`. Its message is not shown to anyone.
- In `complete_verify`, return `False`.
- In either, a `ValueError`, `TypeError` or `KeyError` (for example from a
  malformed payload) is treated exactly like a wrong code. Let those propagate.
  Do not catch them to show a more specific message: a different response for
  each failure tells an attacker which check failed.
- Any other exception is a server error.

## Things to get right

**`begin_*` runs on every page load**, including a refresh and the page shown
again after a wrong code. The example shows a fresh token each time, which is
harmless. A factor that sends something must reuse a code that is still valid
rather than send a new one each time, as `EmailAdapter` does.

**Make single use hold under concurrency.** Two requests with the same code can
arrive together. Spend it in one database operation whose result says whether
you won, as the example does with `delete()`.

**Store state in `Authenticator.data`**, a `JSONField`. There is no per-factor
table.

**Hash what you only need to compare.** `data` is stored as plain JSON, readable
by anyone who can read the table. Use `make_password` and `check_password`, as the
example and recovery codes do. A secret you must read back, such as a TOTP seed,
cannot be hashed. Compare plain values with `django_mfa.utils.strings_equal`,
never `==`, so the comparison takes the same time whatever the input.

**Call `authenticator.record_usage()` after a successful verification**, so the
security page can show when the method was last used.

## Known limitations

- **Display names.** `Authenticator.Type` lists only the built-in types, so for
  your rows `get_type_display()` returns the raw type (`backup_token`). That is
  what the security page's list of methods, the notification emails and the JSON
  API show for a row. If it matters, replace `security.html` and label each row
  from the matching entry in `enabled_adapters`, whose `verbose_name` is right.
- **No database constraint for one-per-user.** The database allows only one
  `totp`, `recovery_codes` and `email` row per user. For your type,
  `supports_multiple = False` only hides the "Add a method" link: a user who
  types the enroll URL can still submit it. Check in `complete_enroll`, as the
  example does.
- **`MFA_FACTORS` lists built-ins only.** Your factor is registered by your own
  `ready()`. Naming it in `MFA_FACTORS` raises `ImproperlyConfigured`. Use your
  own setting if you need to switch it off.
- **Registering twice raises `ValueError`.** If your `ready()` can run more than
  once (some test setups), check `registry.all()` before registering.

## Checklist for a new factor

1. An `Adapter` subclass with `type`, `verbose_name`, the flags you need, and
   the four methods (`begin_enroll` and `complete_enroll` only if
   `supports_enroll` is true).
2. `registry.register(YourAdapter())` in your app's `AppConfig.ready()`.
3. Two templates, `django_mfa/enroll_<type>.html` and
   `django_mfa/verify_<type>.html`, extending `base_template` and posting the
   fields your `complete_*` methods read, plus `next` on the verify page.
4. Tests: a successful enroll, a successful verify, a wrong attempt returning
   400, and whatever your factor promises beyond that (single use, one per
   user, not counting as primary).
