# Customizing the UI

django-mfa ships working screens so you don't have to build them, not so you have to
keep them. Everything below is overridable, in roughly increasing order of effort.

## Start here: point at your own base template

Every django-mfa page extends whatever `MFA_BASE_TEMPLATE` names, and the built-in
`django_mfa/base.html` exists only so the package works before you've configured
anything. Replacing it is usually the entire job:

    MFA_BASE_TEMPLATE = "base.html"      # your project's own base template

Your template needs to provide one thing: a `{% block content %}` for the pages to
fill. If yours already has one (most do), you are finished — the MFA screens now
carry your navigation, your CSS, and your footer.

If your base block has a different name, wrap it rather than renaming everything:

    {% comment %} myapp/templates/mfa_base.html {% endcomment %}
    {% extends "base.html" %}
    {% block main %}{% block content %}{% endblock %}{% endblock %}

    MFA_BASE_TEMPLATE = "mfa_base.html"

The built-in pages also set a `title` context variable where relevant, which
`django_mfa/base.html` renders as `{{ title|default:_("Two-factor authentication") }}`.
Use it in your own base template if you want per-page titles.

`base.html` exposes two blocks of its own: `nav_menu` (the small header bar) and
`main_modifier` (an extra class on `<main>`, which the security page uses to widen
itself). An earlier release also had an empty `left_bar` block for a sidebar column
that was never filled; it is gone.

## Replacing individual pages

Templates are loaded by path, so an app listed **before** `django_mfa` in
`INSTALLED_APPS` — or any directory in `TEMPLATES["DIRS"]` — can shadow any of them
by putting a file at the same path:

    myproject/templates/django_mfa/security.html

The full set:

| Template | Rendered by | When |
|---|---|---|
| `django_mfa/base.html` | all pages | the default `MFA_BASE_TEMPLATE` |
| `django_mfa/security.html` | `mfa:security_settings` | the account's MFA overview |
| `django_mfa/picker.html` | `mfa:verify` | at login, when the user holds more than one method |
| `django_mfa/enroll_totp.html` | `mfa:enroll_factor` | setting up an authenticator app |
| `django_mfa/enroll_webauthn.html` | `mfa:enroll_factor` | registering a security key or passkey |
| `django_mfa/enroll_email.html` | `mfa:enroll_factor` | confirming an emailed one-time code (`"email"` in `MFA_FACTORS`, off by default — see {doc}`security`) |
| `django_mfa/verify_totp.html` | `mfa:verify_factor` | the TOTP challenge |
| `django_mfa/verify_webauthn.html` | `mfa:verify_factor` | the WebAuthn challenge |
| `django_mfa/verify_recovery_codes.html` | `mfa:verify_factor` | the recovery-code challenge |
| `django_mfa/verify_email.html` | `mfa:verify_factor` | the emailed-code challenge |
| `django_mfa/recovery_codes.html` | `mfa:recovery_codes` | displaying freshly generated codes |

Enroll and verify templates are resolved from the factor type, as
`django_mfa/enroll_<type>.html` and `django_mfa/verify_<type>.html`. That naming is
the contract — it's also how a custom factor gets its screens, with no view changes
(see {doc}`custom_factors`).

## Template context

What each page gives you. Every page additionally receives `base_template`, which is
what the `{% extends base_template %}` line at the top resolves.

### `security.html`

| Variable | What it is |
|---|---|
| `enabled_adapters` | Adapters this user holds at least one of. Distinct *types*. |
| `available_adapters` | Adapters the user could still add. Already excludes singletons they hold and factors that aren't enrolled at all. Link each to `{% url 'mfa:enroll_factor' adapter.type %}`. |
| `authenticators` | The individual `Authenticator` rows, ordered by type then creation. This — not `enabled_adapters` — is what lets you list three security keys separately so a user can tell them apart and remove exactly one. |
| `recovery_codes_remaining` | Integer count of unused codes. |
| `owned_by_enterprise` | The `MFA_OWNED_BY_ENTERPRISE` setting, so the template can hide the remove button for WebAuthn. |
| `mfa_enrollment_required` | `True` only when this user is both required to hold a factor (`MFA_REQUIRED`, see {doc}`enforcement`) and holds none yet — i.e. exactly when `MfaMiddleware` walled them onto this page. If you shadow this template, render something here: without it, a required user lands on a security page that gives no reason for the wall they just hit. |
| `grace` | A `policy.GraceState` (`required_at`, `days_remaining`) when this user would be required to enrol but is not yet, else `None`. |

### `picker.html`

| Variable | What it is |
|---|---|
| `adapters` | Every method this user can verify with **right now**, including recovery codes. Link each to `{% url 'mfa:verify_factor' adapter.type %}`. |

The picker is only rendered when the user has more than one method — with exactly
one, the view redirects straight to that method's challenge. Don't rely on this page
being seen.

### Enroll pages

| Variable | What it is |
|---|---|
| `adapter` | The adapter being enrolled. `adapter.verbose_name` is the display name. |
| `error_message` | Present only after a failed POST; the page re-renders with HTTP 400. |
| *(TOTP)* `secret_key` | The freshly generated Base32 secret. Must be POSTed back in a hidden field — the server does not stash it in the session. |
| *(TOTP)* `provisioning_uri` | The `otpauth://` URI. Render it with `{% qrcode provisioning_uri "alt text" %}`. |
| *(WebAuthn)* `options` | JSON ceremony options. Render with `{% webauthn_options_script options "webauthn-options" %}`. |
| *(email)* `address` | The account's address, masked (`a****n@example.com`) — never the plaintext. `None` when the account has no usable address; `enroll_email.html` shows a "no address on file" message instead of the form in that case (guard on it if you shadow this page). |
| *(email)* `code_length` | Digit count of the code just emailed — tracks `MFA_EMAIL_CODE_LENGTH` rather than assuming 6, so the input's `maxlength` and label stay correct if you change that setting. Only present alongside a non-`None` `address`. |

### Verify pages

| Variable | What it is |
|---|---|
| `adapter` | The adapter being challenged. |
| `next` | Where to redirect after success, already validated against open redirects. Pass it through in a hidden field named `next`. |
| `error_message` | Present only after a failed attempt; the page re-renders with HTTP 400. |
| *(recovery codes)* `remaining` | How many unused codes are left, so you can warn people running low. |
| *(WebAuthn)* `options` | JSON ceremony options, as above. |
| *(email)* `address` | The enrolled address, masked — the address captured at enrollment time, not necessarily the account's current one (see {doc}`security`). `None` when there is no live ceremony to challenge (e.g. the factor was removed after this page was linked to); `verify_email.html` shows a fallback message instead of the form in that case (guard on it if you shadow this page). |
| *(email)* `code_length` | Digit count of the code just emailed, as on the enroll page above. Only present alongside a non-`None` `address`. |

### `recovery_codes.html`

| Variable | What it is |
|---|---|
| `codes` | A list of plaintext codes on the visit that generates them, and `None` on every visit after. Codes are hashed at rest and cannot be shown twice — your template must handle `None`. |
| `next_url` | Resolved `LOGIN_REDIRECT_URL`, for the "done" link. |

## The QR code

`{% qrcode provisioning_uri "Scan this code" %}` (from `{% load otp_tags %}`) renders
an inline SVG data URI. It is generated entirely server-side — no third-party
service, no external request, and your users' TOTP secrets never leave your process.
If you replace `enroll_totp.html`, keep using this tag rather than a QR image API.

## Rules for the WebAuthn templates

WebAuthn pages are driven by `django_mfa/static/django_mfa/webauthn.js`, which finds
its elements **by ID**. Restyle these pages freely, but keep the IDs and the
`name` attributes — the script silently does nothing if they're missing, and it will
look like the button is simply dead.

`enroll_webauthn.html` and `verify_webauthn.html` need:

| Hook | Why |
|---|---|
| `id="webauthn-form"` with `data-mode="create"` (enroll) or `data-mode="get"` (verify) | The form the script drives; `data-mode` picks the ceremony. |
| `id="webauthn-start"` | The button the script binds its click handler to. Keep it `type="button"`. |
| `<input name="credential">` | Where the script writes the ceremony result before submitting. |
| `id="webauthn-options"` via `{% webauthn_options_script options "webauthn-options" %}` | The ceremony options. Use the tag — see below. |
| `id="webauthn-unsupported"` | Shown when the browser has no WebAuthn support. |
| `id="webauthn-error"` | Where ceremony errors are written. |

For a passkey button on your own login page the IDs are
`webauthn-passkey-form`, `webauthn-passkey-start`, `webauthn-passkey-unsupported`
and `webauthn-passkey-error` — see {doc}`recipes`.

:::{warning}
**Use `{% webauthn_options_script %}`, not `{{ options|json_script:"..." }}`.**
`options` is already a JSON *string*. Django's built-in `json_script` filter would
encode it a second time, so the browser's single `JSON.parse()` hands back the
original JSON text as a string instead of an object, `options.publicKey` comes out
`undefined`, and the ceremony never starts. This breaks only in a real browser —
every server-side test still passes, because the page rendered fine.
:::

The bundled stylesheet (`static/django_mfa/style.css`) carries one rule that is not
cosmetic:

    [hidden] { display: none !important; }

The HTML `hidden` attribute is implemented by a user-agent rule whose specificity
loses to *any* class selector that sets `display`. Without the `!important`, a
`.mfa-alert { display: block }` beats it and the "your browser does not support
WebAuthn" banner shows permanently — on browsers that support it perfectly well. If
you replace the stylesheet entirely, carry that rule over.

## Text and translation

Every string is wrapped in `{% trans %}` / `{% blocktrans %}` and ships under the
`django_mfa` app, so `makemessages` picks it up like any other app's text. To change
wording without translating, override the template.

## Styling without touching templates

The bundled stylesheet is self-contained — no framework, no webfont, no network
request of any kind, because these pages sit in a login flow and have to render on a
locked-down network. It adapts to `prefers-color-scheme`, so dark mode works out of
the box, and it is built from CSS custom properties: if you only want to match your
brand colour, redefine the tokens instead of forking anything.

    :root {
      --mfa-accent: #7c3aed;
      --mfa-radius: 4px;
    }

The structural class names are `mfa-`-prefixed and stable:

| Class | Where |
|---|---|
| `.mfa-card` | Each panel/section |
| `.mfa-list` / `.mfa-item` | The enrolled-methods list on the security page |
| `.mfa-picker` | The method chooser, and "add a method" |
| `.mfa-actions` | A row of buttons (stacks full-width under 26rem) |
| `.mfa-alert` | Error banners, including the WebAuthn ones |
| `.mfa-code-input` | The one-time-code field |
| `.recovery-code` | Each individual recovery code |
| `.qrcode` | The TOTP QR image |

`.btn` / `.btn-primary` / `.btn-default` / `.btn-danger`, `.form-control`,
`.help-block` and `.text-danger` are kept under their conventional names so a host
project already loading a CSS framework gets a reasonable result either way.
