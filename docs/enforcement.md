# Requiring MFA

By default MFA is optional: `MfaMiddleware` challenges a user only after they enroll a
factor, and never asks anyone to enroll (see {doc}`mfa_flow`). This page shows how to
make it mandatory.

## Choose your tool

| To require a second factor for | Use |
|---|---|
| Every user, or the users a rule picks (staff, a group) | [`MFA_REQUIRED`](#require-mfa-for-users) |
| Anyone who opens a particular view | [`@mfa_required` / `MfaRequiredMixin`](#require-mfa-on-a-view) |
| A fresh challenge before a sensitive action | [`@mfa_recent_required` / `MfaRecentRequiredMixin`](#step-up-re-authentication) |
| Every page of the Django admin | [`MFA_PROTECT_ADMIN` / `MfaAdminMixin`](#protecting-the-admin) |

You can combine them. `MFA_REQUIRED` picks users; the decorators and the admin gate
pick pages and apply to everyone who reaches them. A [grace period](#rolling-it-out)
or an [exemption](#exempting-a-user) relaxes `MFA_REQUIRED` only.

## Keep logout reachable

```python
# settings.py
MFA_EXEMPT_PATHS = ["/accounts/logout/"]  # your logout URL, exactly as in request.path
```

Do this first. `MfaMiddleware` redirects a walled user on every request, logout
included, unless the path is listed here. Without it, a user who cannot present their
factor, or cannot enroll one right now, has no way to sign out. Paths match exactly,
not by prefix. The admin's "Log out" link is no substitute (see
[Protecting the admin](#protecting-the-admin)).

## Require MFA for users

```python
# settings.py
from django_mfa.policy import in_groups, is_staff

MFA_REQUIRED = True                            # every authenticated user
MFA_REQUIRED = is_staff                        # users with is_staff = True
MFA_REQUIRED = in_groups("admins", "finance")  # members of any listed group
MFA_REQUIRED = "myapp.policy.needs_mfa"        # your own predicate: (user) -> bool
```

Pick one. The default, `False`, requires nobody. Any callable that takes a user and
returns a bool works, or its dotted path. `in_groups()` returns a predicate, so call it
once with every group name; each time that predicate runs it makes one query.
`manage.py check` fails with `django_mfa.E004` if the value cannot be imported or is
not callable.

`MfaMiddleware` enforces this setting; without it in `MIDDLEWARE`, `MFA_REQUIRED` does
nothing. A user it applies to who holds no factor is sent to the security page on every
request until they enroll (see [What a walled user sees](#what-a-walled-user-sees)).

**Cost:** once `MFA_REQUIRED` is on, `MfaMiddleware` makes one query per authenticated
request to check whether the user holds a factor. Your predicate then runs only for
users who hold none, on each of their requests.

**Check it worked:** `python manage.py mfa_report` lists the users `MFA_REQUIRED`
applies to who have not enrolled yet.

## Require MFA on a view

```python
# views.py
from django.views.generic import TemplateView
from django_mfa.decorators import MfaRequiredMixin, mfa_required

@mfa_required
def billing(request):
    ...

class BillingView(MfaRequiredMixin, TemplateView):  # mixin first
    ...
```

| Who reaches the view | Result |
|---|---|
| Not logged in | Redirected to `LOGIN_URL` |
| Holds no factor (recovery codes alone don't count) | Redirected to `mfa:security_settings` |
| Holds a factor, not verified in this session | Redirected to `mfa:verify`, then back |
| Verified in this session | The view runs |

This applies to everyone who reaches the view, whatever `MFA_REQUIRED` says: a
decorated view requires a factor even when `MFA_REQUIRED = False`, and grace periods
and exemptions do not open it. It does not need `MfaMiddleware`. Neither form takes
options; use the step-up versions below if you need any.

## Step-up re-authentication

Use this when a verified session is not enough and the user must have passed a
challenge recently:

```python
# views.py
from django.views.generic import FormView
from django_mfa.decorators import MfaRecentRequiredMixin, mfa_recent_required

@mfa_recent_required(max_age=60)
def transfer_funds(request):
    ...

class TransferView(MfaRecentRequiredMixin, FormView):  # mixin first
    mfa_stepup_max_age = 60
```

Both run every check `@mfa_required` does first. Then, if the last challenge is older
than `max_age` seconds, the user goes through `mfa:verify` again. A `GET` returns to
the same URL afterwards. A `POST` body cannot survive the redirect, so the user lands on
`mfa:security_settings` (or your `next_url`) and submits again.

| Decorator argument | Mixin attribute | Default | Meaning |
|---|---|---|---|
| `max_age` | `mfa_stepup_max_age` | `MFA_STEPUP_MAX_AGE` (300) | Seconds since the last challenge |
| `next_url` | `mfa_stepup_next_url` | `mfa:security_settings` | Path an unsafe request returns to |
| `allow_unenrolled` | `mfa_allow_unenrolled` | `False` | Let a user with no factor through |

Leave `allow_unenrolled` at `False` unless the view is part of a user's first
enrollment; django-mfa's own enroll and recovery-codes views set it so a user with no
factor can still get one. `@mfa_recent_required` also works without parentheses.

django-mfa already applies step-up to its own views that add or remove a factor or show
recovery codes, so a stolen session cannot replace the user's factors without passing a
fresh challenge.
`MFA_STEPUP_MAX_AGE = None` turns step-up off for those views and for any of yours that
don't pass `max_age`. Any other value must be a positive integer, or `manage.py check`
fails with `django_mfa.E005`.

## Protecting the admin

```python
# settings.py
MFA_PROTECT_ADMIN = True
```

Every page on the default admin site (`django.contrib.admin.site`) now needs a verified
session. Staff who have not passed the challenge are sent to `mfa:verify` (not back to
the login form), staff with no factor to `mfa:security_settings`. Anonymous visitors
still see the admin login form. The admin site enforces this itself, so it works
without `MfaMiddleware`.

The setting also adds `is_staff` to `MFA_REQUIRED`, keeping your own value. With
`MfaMiddleware` installed, factorless staff are therefore walled off the rest of the
site too, and every authenticated request pays the
[one query](#require-mfa-for-users) that `MFA_REQUIRED` costs.

**Grace periods and exemptions do not apply here.** From the moment you deploy, a staff
user with no factor is refused on every admin page.

**The admin's "Log out" link cannot get a walled user out.** Django answers a request to
`admin:logout` that fails the permission check with a redirect to the admin index,
without logging out. Your site's own logout URL, outside `/admin/`, must be in
`MFA_EXEMPT_PATHS` ([Keep logout reachable](#keep-logout-reachable)).

### A custom admin site

`MFA_PROTECT_ADMIN` changes only the default `admin.site`. Your own `AdminSite`
instance gets no protection from it, and nothing warns you. Mix in `MfaAdminMixin`:

```python
# myproject/admin.py
from django.contrib.admin import AdminSite
from django_mfa.admin_site import MfaAdminMixin

class MyAdminSite(MfaAdminMixin, AdminSite):
    site_header = "My admin"

admin_site = MyAdminSite(name="myadmin")
```

The mixin gates the admin pages only. It does not add staff to `MFA_REQUIRED`; set
`MFA_REQUIRED = is_staff` as well if you want that.

### Fresh challenges in the admin

```python
# settings.py
MFA_PROTECT_ADMIN = True
MFA_ADMIN_STEPUP = True
```

Admin pages then need a challenge within `MFA_STEPUP_MAX_AGE`. With the default of 300
seconds, staff are challenged every five minutes, and a form submitted after the window
is not saved (they verify and return to the page). A site built with
[`MfaAdminMixin`](#a-custom-admin-site) reads `MFA_ADMIN_STEPUP` too, so you can use
it without `MFA_PROTECT_ADMIN` there. With neither, it does nothing and
`manage.py check` fails with `django_mfa.E011`.

## Rolling it out

To give existing users time to enroll instead of walling them all at once:

```python
# settings.py
import datetime

MFA_REQUIRED_FROM = datetime.date(2027, 3, 1)  # nobody is walled before this
MFA_GRACE_PERIOD = 14                          # days (or a timedelta) per user
```

Each user is walled from the **later** of `MFA_REQUIRED_FROM` and their join date plus
`MFA_GRACE_PERIOD`. Existing users share the cutover; anyone who signs up after it
still gets a full window:

| User | Joined | Joined + 14 days | Walled from |
|---|---|---|---|
| Alice | 2024-05-02 | 2024-05-16 | 2027-03-01 (the cutover is later) |
| Bob | 2027-03-10 | 2027-03-24 | 2027-03-24 (his own window is later) |

Either setting works alone. A bare date means midnight at the start of that day.
`manage.py check` fails with `django_mfa.E010` for grace settings that cannot work,
such as a string date or a negative period.

The window starts from `user.date_joined`. To start it from something else (say, the
day a user moved to a plan that requires MFA), set `MFA_GRACE_ANCHOR` to a callable or
dotted path taking a user and returning a `datetime`. If it returns `None`, that user
gets only `MFA_REQUIRED_FROM`, or no grace if that is unset.

To show users their deadline, add `"django_mfa.context_processors.mfa"` to
`TEMPLATES[0]["OPTIONS"]["context_processors"]`, then:

```html+django
{# base.html #}
{% if mfa_grace %}
  <p>Set up two-factor authentication by {{ mfa_grace.required_at|date }}
     ({{ mfa_grace.days_remaining }} days left).</p>
{% endif %}
```

`mfa_grace` is set only while the user is inside their window; `days_remaining` rounds
up. The same value is the security page's `grace` context variable (the shipped
template does not show it) and the `grace` field of the JSON API's `state` response.

**Check it worked:** `python manage.py mfa_status alice` prints `In grace until ...`,
and `mfa_report` marks in-grace users (its CSV output adds a `grace_until` column).

:::{warning}
Grace periods and exemptions change `MFA_REQUIRED` only. They do not open
`@mfa_required` views, or the admin under `MFA_PROTECT_ADMIN`. `mfa_status` describes
`MFA_REQUIRED` only, so `Required: no`, `In grace until` or `Exempt:` does not mean the
admin will let that user in.
:::

## Exempting a user

```bash
python manage.py mfa_disable alice --reason "service account" --until 2027-12-31
python manage.py mfa_disable alice --revoke
```

`alice` is a username or pk. The exemption stops `MFA_REQUIRED` walling that user.
`--reason` is required. `--until` takes `YYYY-MM-DD` and covers that whole day; leave it out for a
permanent exemption. Like grace, it does not open decorated views or the admin.

Revoke with the command, not by deleting the row in the admin. Both remove the
exemption, but only the command sends the `mfa_exemption_changed` signal to your audit
receivers.

## What a walled user sees

A user `MFA_REQUIRED` applies to who holds no factor is redirected to the security page
(`mfa:security_settings`), which tells them a factor is required. Until they enroll,
they can reach only the security page, the enroll pages, the recovery codes page, the
paths in `MFA_EXEMPT_PATHS`, and the JSON API if you mounted it (it runs its own checks;
see {doc}`rest_api`).

The wall lifts once they enroll any factor other than recovery codes. Recovery codes
alone never lift it, because they run out.

The redirect adds `?next=<original path>`, but the shipped views ignore it: after
enrolling, the user lands on the recovery codes page (first time) or the security page.
To send them back where they started, read `next` in your own template or view.

If you override `django_mfa/security.html`, show a message when
`mfa_enrollment_required` is true, or the user gets no reason for the redirect (see
{doc}`customizing`).

## What is not enforced

- **Logging in.** Every check here applies to an authenticated session. Your login and
  password-reset views are yours to protect.
- **Step-up on your own views.** django-mfa applies it only to its own factor
  management views. Add [`@mfa_recent_required`](#step-up-re-authentication) to other
  sensitive views, such as a password change (see {doc}`security`).
- **A custom admin site.** `MFA_PROTECT_ADMIN` covers only the default `admin.site`;
  use [`MfaAdminMixin`](#a-custom-admin-site).
