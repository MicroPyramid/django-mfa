# Customizing the UI

Three ways to make the MFA screens fit your site, in order of effort. Most
projects only need the first.

1. [Use your own base template](#use-your-own-base-template).
2. [Restyle the bundled pages](#restyle-the-bundled-pages) with CSS custom
   properties.
3. [Replace individual templates](#replace-individual-templates).

The rest of the page is reference: each template's context, and the rules the
WebAuthn pages must follow.

## Use your own base template

```python
# settings.py
MFA_BASE_TEMPLATE = "base.html"
```

Your template needs a `{% block content %}`, which every MFA page fills. Open the
security page (`/mfa/security/` if you mounted the URLs at `mfa/`) and you should
see it inside your own header and footer.

The bundled stylesheet, `django_mfa/style.css`, is linked only from the default
base template, so with your own the pages use your CSS. Their classes are listed
under [Class names](#class-names).

### If your content block has another name

Point the setting at a wrapper template instead. This one maps a `main` block to
`content`, and loads the bundled stylesheet on the MFA pages only:

```html+django
{# templates/mfa_base.html #}
{% extends "base.html" %}
{% load static %}
{% block extra_head %}{{ block.super }}<link rel="stylesheet" href="{% static 'django_mfa/style.css' %}">{% endblock %}
{% block main %}{% block content %}{% endblock %}{% endblock %}
```

```python
# settings.py
MFA_BASE_TEMPLATE = "mfa_base.html"
```

Replace `extra_head` with your base template's head block, or drop that line. The
bundled stylesheet also styles `body`, headings, links and form controls, so it
changes your header's look on those pages too.

### Keep the bundled layout, change the header

The default base template has a `nav_menu` block for its header bar (and a
`main_modifier` block, which the security page uses to widen `<main>`). Override
the header in a wrapper, and point `MFA_BASE_TEMPLATE` at it as above:

```html+django
{# templates/mfa_base.html #}
{% extends "django_mfa/base.html" %}
{% block nav_menu %}
<header class="mfa-header">
  <div class="mfa-header__inner"><a class="mfa-brand" href="/">Acme</a></div>
</header>
{% endblock %}
```

## Restyle the bundled pages

Load your own stylesheet after `django_mfa/style.css`, and redefine the custom
properties it is built from:

```css
/* static/css/mfa.css, loaded after django_mfa/style.css */
:root {
  --mfa-accent: #7c3aed;
  --mfa-accent-hover: #6d28d9;
  --mfa-focus: #7c3aed;
  --mfa-radius: 4px;
  --mfa-radius-sm: 4px;
}
```

Link it from your own base template or a wrapper like the one above. The default
base template has no head block to extend; to keep it, replace
`django_mfa/base.html` with a copy that adds your `<link>`.

### Custom properties

| Property | Controls |
|---|---|
| `--mfa-bg` | Page background |
| `--mfa-surface` | Cards, the header bar, inputs and buttons |
| `--mfa-surface-alt` | Subtle fills: the QR panel, the recovery-code grid, `<code>`, hover backgrounds |
| `--mfa-text` | Body and heading text |
| `--mfa-muted` | Secondary text: intros, hints, dates |
| `--mfa-border` | Card borders and list dividers |
| `--mfa-border-strong` | Borders of inputs, secondary buttons and method links |
| `--mfa-accent` | Links, primary buttons, focused inputs |
| `--mfa-accent-hover` | Primary buttons on hover |
| `--mfa-on-accent` | Text on primary buttons |
| `--mfa-focus` | Keyboard focus outline |
| `--mfa-danger` | Error text, and the "Remove" button's text |
| `--mfa-danger-bg` | Error banner background, and the "Remove" button on hover |
| `--mfa-danger-border` | Error banner border |
| `--mfa-radius` | Card corners |
| `--mfa-radius-sm` | Corners of buttons, inputs, method links and error banners |
| `--mfa-shadow` | Card shadow |

The colour properties get different values inside
`@media (prefers-color-scheme: dark)`. A `:root` rule of yours outside a media
query applies in both modes, so put dark-mode values in a dark-mode media query of
your own. The "MFA is required" notice (`.mfa-notice--warning`) uses fixed colours,
not these properties.

### Class names

| Class | Where |
|---|---|
| `.mfa-header`, `.mfa-header__inner`, `.mfa-brand` | The header bar of `django_mfa/base.html` |
| `.mfa-main`, `.mfa-main--wide` | `<main>`; the security page is the wide one |
| `.mfa-card`, `.mfa-card__title` | Each panel, and a panel's heading row |
| `.mfa-lede`, `.mfa-muted`, `.mfa-empty` | Intro text, secondary text, "nothing here yet" text |
| `.mfa-notice`, `.mfa-notice--warning` | The "MFA is required" notice on the security page |
| `.mfa-list`, `.mfa-item`, `.mfa-item__text`, `.mfa-item__name`, `.mfa-item__meta` | The list of enrolled methods |
| `.mfa-picker` | The method chooser, and the "Add a method" list |
| `.mfa-actions` | A row of buttons; stacks full width below 26rem |
| `.mfa-alert` | Error banners, including the WebAuthn ones |
| `.mfa-code-input`, `.mfa-code-input--wide` | The one-time code field; the wide one is for recovery codes |
| `.mfa-qr`, `.qrcode`, `.mfa-secret` | The TOTP QR panel, the QR image, the secret to type in |
| `.mfa-codes`, `.recovery-code` | The recovery-code grid, and each code |

Buttons and forms use the common names `.btn`, `.btn-primary`, `.btn-default`,
`.btn-danger`, `.btn-sm`, `.form-group`, `.form-control`, `.help-block` and
`.text-danger`, so a CSS framework that defines them styles the pages without the
bundled stylesheet.

## Replace individual templates

Put a file at the same path in a directory listed in `TEMPLATES["DIRS"]`, or in
the `templates/` folder of an app listed before `django_mfa` in `INSTALLED_APPS`:

```text
templates/django_mfa/verify_totp.html
```

Start from a copy of the original. This prints where they are installed:

```bash
python -c "import django_mfa, pathlib; print(pathlib.Path(django_mfa.__file__).parent / 'templates' / 'django_mfa')"
```

Text you keep unchanged inside `{% trans %}` keeps its translations. Text you
change or add is yours to translate; see {doc}`translations`.

| Template | URL name | Shown |
|---|---|---|
| `django_mfa/base.html` | (all pages) | The default `MFA_BASE_TEMPLATE` |
| `django_mfa/security.html` | `mfa:security_settings` | The user's methods, "Add a method", recovery codes |
| `django_mfa/picker.html` | `mfa:verify` | At login, to a user with more than one method |
| `django_mfa/enroll_totp.html` | `mfa:enroll_factor` | Setting up an authenticator app |
| `django_mfa/enroll_webauthn.html` | `mfa:enroll_factor` | Registering a security key or passkey |
| `django_mfa/enroll_email.html` | `mfa:enroll_factor` | Confirming an emailed code (when `"email"` is in `MFA_FACTORS`) |
| `django_mfa/verify_totp.html` | `mfa:verify_factor` | The authenticator-app challenge |
| `django_mfa/verify_webauthn.html` | `mfa:verify_factor` | The security key or passkey challenge |
| `django_mfa/verify_recovery_codes.html` | `mfa:verify_factor` | The recovery-code challenge |
| `django_mfa/verify_email.html` | `mfa:verify_factor` | The emailed-code challenge |
| `django_mfa/recovery_codes.html` | `mfa:recovery_codes` | Newly generated recovery codes |
| `django_mfa/email/*.txt` | (none) | The emails; see [Emails](#emails) |

Enroll and verify pages are named after the factor type:
`django_mfa/enroll_<type>.html` and `django_mfa/verify_<type>.html`. A custom
factor gets its pages the same way; see {doc}`custom_factors`.

## Template context

Every page receives `base_template` (the value of `MFA_BASE_TEMPLATE`) and starts
with `{% extends base_template %}`.

### `security.html`

| Variable | What it is |
|---|---|
| `authenticators` | The user's `Authenticator` rows, by type then date added: one per security key, so a user can tell them apart. Each has `pk`, `type`, `name`, `created_at`, `last_used_at` and `get_type_display`. |
| `enabled_adapters` | One adapter per method type the user holds, recovery codes included. |
| `available_adapters` | Adapters the user can still add. Link each to `{% url 'mfa:enroll_factor' adapter.type %}`, labelled `adapter.verbose_name`. |
| `recovery_codes_remaining` | Number of unused recovery codes. |
| `owned_by_enterprise` | The `MFA_OWNED_BY_ENTERPRISE` setting. When true, hide the remove button on WebAuthn rows; the server refuses to remove them anyway. |
| `mfa_enrollment_required` | True when `MFA_REQUIRED` applies to the user and they hold no method other than recovery codes, which is when the middleware sends them here. Say why, or they arrive with no explanation. |
| `grace` | While `MFA_REQUIRED` applies to the user and their grace period is running: an object with `required_at` and `days_remaining`. Otherwise `None`. Set whether or not they have enrolled; see {doc}`enforcement`. |

To remove a method, POST its `pk` to `{% url 'mfa:manage' %}` with a CSRF token.

### `picker.html`

| Variable | What it is |
|---|---|
| `adapters` | Every method the user can verify with, recovery codes included. Link each to `{% url 'mfa:verify_factor' adapter.type %}`. |
| `next` | Where to go after verifying, or `None`. Append it to each link as `?next={{ next\|urlencode }}`. |

A user with exactly one method skips this page and goes straight to that method.

### Enroll and verify pages

All of them receive `adapter` (`adapter.verbose_name` is the display name) and,
after a failed attempt, `error_message`; the page is then returned with HTTP 400.
Verify pages also receive `next`, already checked against open redirects: send it
back in a hidden field named `next`.

Each factor adds its own variables and reads its own POST fields. Keep the field
names if you replace a page.

| Page | Extra context | Fields to POST |
|---|---|---|
| `enroll_totp.html` | `secret_key`, `provisioning_uri` | `secret_key` (hidden; the server does not keep it), `code` |
| `verify_totp.html` | none | `code`, `next` |
| `enroll_webauthn.html` | `options` | `credential` (filled in by the script), `name` (optional label, up to 100 characters) |
| `verify_webauthn.html` | `options` | `credential`, `next` |
| `verify_recovery_codes.html` | `remaining` (unused codes left) | `code`, `next` |
| `enroll_email.html` | `address`, `code_length` | `code` |
| `verify_email.html` | `address`, `code_length` | `code`, `next` |

On the email pages, `address` is masked (`a****n@example.com`). It is `None` when
there is nothing to send to (no usable address on the account, or no email factor
to verify); show a message instead of the form, as the bundled templates do.
`code_length` follows `MFA_EMAIL_CODE_LENGTH`; use it for the input's `maxlength`.

### `recovery_codes.html`

| Variable | What it is |
|---|---|
| `codes` | The new codes on the visit that generates them, and `None` on every visit after. They are stored hashed and cannot be shown twice. |
| `next_url` | `LOGIN_REDIRECT_URL`, resolved, for the "Done" link. |

### Emails

Each email is `django_mfa/email/<name>.txt` for the body and
`django_mfa/email/<name>_subject.txt` for the subject, which is collapsed onto one
line.

| Name | Sent when | Context |
|---|---|---|
| `otp_code` | An emailed code is issued | `code`, `user`, `validity_minutes` |
| `factor_added` | A method is added | `user`, `factor`, `name` |
| `factor_removed` | A method is removed | `user`, `factor`, `name` |
| `mfa_disabled` | A removal leaves no method except recovery codes | `user` |
| `recovery_code_used` | A recovery code is used | `user`, `remaining` |

All but `otp_code` are sent only when `MFA_NOTIFY_ON_CHANGE` is on. `factor` is
the method's display name and `name` a security key's label (often empty).
`MFA_EMAIL_SUBJECT`, when set, replaces `otp_code_subject.txt`.

## The QR code tag

```html+django
{% load otp_tags %}
{% qrcode provisioning_uri "Scan this code with your authenticator app" %}
```

This renders an `<img class="qrcode">` holding an SVG drawn on your server, so the
TOTP secret never goes to another service. Keep using it if you replace
`enroll_totp.html`. `otp_tags` also has the `mask_email` filter the security page
uses.

## WebAuthn template contract

`django_mfa/static/django_mfa/webauthn.js` drives the security key pages and
finds its elements by `id`. Restyle freely, but keep the elements below. Without
any of the first five, the button does nothing or fails after the browser prompt,
usually with no message on the page.

`enroll_webauthn.html` and `verify_webauthn.html` need:

| Element | Purpose |
|---|---|
| `<form id="webauthn-form" data-mode="create">` (enroll) or `data-mode="get"` (verify) | The form the script submits. `data-mode` picks registration or sign-in. |
| `<input type="hidden" name="credential">` inside the form | The script writes the browser's response here. |
| `<button type="button" id="webauthn-start">` | Starts the ceremony; the script submits the form itself. A submit button would post an empty credential. |
| `{% webauthn_options_script options "webauthn-options" %}` | Writes the options into `<script id="webauthn-options">`. Needs `{% load webauthn_tags %}`. |
| `<script src="{% static 'django_mfa/webauthn.js' %}" defer></script>` | The script. It starts on `DOMContentLoaded`, so load it before that fires. |
| `<div id="webauthn-unsupported" hidden>` | Revealed when the browser has no WebAuthn. Must render with `hidden`. |
| `<p id="webauthn-error">` | Where the script writes ceremony errors. Leave it empty. |

A passkey button on your own login page uses its own ids: `webauthn-passkey-form`
(with `data-begin-url="{% url 'mfa:passkey_begin' %}"`), `webauthn-passkey-start`,
`webauthn-passkey-unsupported` and `webauthn-passkey-error`. See {doc}`recipes`.

:::{warning}
Use `{% webauthn_options_script options "webauthn-options" %}`, not
`{{ options|json_script:"webauthn-options" }}`. `options` is already a JSON
string; `json_script` encodes it again, the browser gets a string instead of an
object, and the ceremony never starts. The page itself renders fine, so only a
real browser shows the failure.
:::

### Keep the `[hidden]` rule

The bundled stylesheet contains:

```css
[hidden] { display: none !important; }
```

Without `!important`, a class that sets `display` (such as
`.mfa-alert { display: block; }`) overrides the `hidden` attribute, and the
"browser not supported" message shows permanently, even in browsers that support
WebAuthn. If you replace the stylesheet, or style these elements with your own
classes, keep this rule.
