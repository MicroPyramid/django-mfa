# Enforcing MFA

Enrollment is opt-in by default. `MfaMiddleware` only challenges a user who already
holds a factor, so someone who never enrolls is never prompted or blocked — see
{doc}`mfa_flow`. This page covers the two ways to change that: requiring MFA of some
or all users, and requiring it for specific views regardless of who's asking — plus
what a required user actually sees before they've enrolled anything.

## Requiring MFA

`MFA_REQUIRED` (`django_mfa.policy`) answers "who must hold a second factor", in one
of four shapes.

**Nobody — the default:**

    MFA_REQUIRED = False

**Every authenticated user:**

    MFA_REQUIRED = True

**Anyone matching a predicate you write** — a callable taking a user and returning a
bool:

    def needs_mfa(user):
        return user.profile.handles_billing

    MFA_REQUIRED = needs_mfa

**A dotted path to one**, resolved with `django.utils.module_loading.import_string` —
useful when you'd rather not import the predicate's module at settings-load time:

    MFA_REQUIRED = "myapp.policy.needs_mfa"

Two predicates ship for the common cases, in `django_mfa.policy`:

    from django_mfa.policy import is_staff, in_groups

    MFA_REQUIRED = is_staff                        # anyone who can reach /admin/
    MFA_REQUIRED = in_groups("admins", "finance")   # anyone in either group

`in_groups(...)` is a factory, not a predicate itself — call it and assign the
result, as above. It costs one query per request
(`user.groups.filter(name__in=names).exists()`), so if you need several different
group-based rules, write your own predicate that checks them together rather than
combining several `in_groups(...)` calls.

`django_mfa.E004` fails `manage.py check` if `MFA_REQUIRED` is a string that doesn't
import, or resolves to something that isn't callable — catching a misconfigured
predicate at startup is a lot cheaper than discovering it from an exception raised
inside the middleware on some user's live request.

### Exempting a user

    manage.py mfa_disable alice --reason "service account" --until 2099-12-31

An exemption suppresses **`MFA_REQUIRED` only**. It does not open
`@mfa_required` views: `MFA_REQUIRED` picks users, the decorator picks views,
and an exempt user reaching a decorated billing page is still redirected.
Revoke with `manage.py mfa_disable alice --revoke`, or by deleting the row in
the admin — both work, but they are not equivalent: only the command path
fires `mfa_exemption_changed`. Deleting the row in the admin is not audited
at all — Django's admin emits no signal of its own for it that django-mfa
listens for. If the deletion needs to appear in whatever is consuming that
signal, use `mfa_disable --revoke`, not the admin.

### Rolling it out

Turning `MFA_REQUIRED` on for a project with existing users is rarely a flag
day — "everyone must have a second factor starting next month" needs a ramp,
not an instant wall. `MFA_REQUIRED_FROM` and `MFA_GRACE_PERIOD` give you one:

    MFA_REQUIRED_FROM = datetime.date(2026, 9, 1)   # nobody is walled before this
    MFA_GRACE_PERIOD = 14                            # ...then 14 days per user, from their own anchor

A user is required from **whichever of `MFA_REQUIRED_FROM` and
`anchor + MFA_GRACE_PERIOD` is later** — `max()`, not `min()`. That single
rule, evaluated per user, covers both halves of a rollout at once:

- **Alice signed up in 2024**, long before the cutover. Her anchor (by
  default `alice.date_joined`) plus 14 days is already in the past, so
  `MFA_REQUIRED_FROM` alone decides: she's walled on 2026-09-01, the same day
  as every other existing user.
- **Bob signs up on 2026-09-10**, after the cutover has already passed. If
  `MFA_REQUIRED_FROM` alone decided, he'd be walled on his very first login —
  the date has already come and gone. Instead `anchor + MFA_GRACE_PERIOD`
  wins the `max()`, so Bob gets his own full 14 days from the day he joined,
  same as anyone who signs up after the ramp is over.

`policy.required_at(user)` returns that date (or `None` if neither setting
applies to the user at all), and `policy.grace_state(user)` returns a
`GraceState(required_at, days_remaining)` while the user is inside their
window — `None` once the policy doesn't apply to them, or once `required_at`
has passed and they're actually walled. `days_remaining` is rounded up and is
for display only; nothing enforces against it, only against `required_at`
itself.

`MFA_GRACE_ANCHOR` exists for the clock `date_joined` can't express: a
dotted path or callable, `(user) -> datetime | None`, for a per-user start
date that isn't "when the account was created" — the day a cohort was
migrated in, or the day a user's plan changed to require 2FA. Return `None`
for a user you have no anchor for; they simply fall back to
`MFA_REQUIRED_FROM` alone.

The grace state is surfaced in five places: `security_settings`'s own
`grace` context key, the opt-in `django_mfa.context_processors.mfa` context
processor (`mfa_grace`, for your own templates), the JSON API's `state`
endpoint (`grace` field), `mfa_status`'s "In grace until" line, and
`mfa_report`, which now lists in-grace users and appends a `grace_until`
column to its CSV output — see the 4.6.0 entry in `CHANGELOG.md`.

:::{warning}
**Grace suppresses `MFA_REQUIRED` only — it does not open `@mfa_required`
views, or the admin gate under `MFA_PROTECT_ADMIN`.** Exactly like an
`MfaExemption` above, a user still inside their grace window is left alone
by the enrollment wall, but a view behind `@mfa_required`/`MfaRequiredMixin`
still refuses them, and so does `/admin/` when `MFA_PROTECT_ADMIN` is on:
both are enforced through `decorators.enforcement_state()`, which is itself
the policy for what it gates and never consults `MFA_REQUIRED` or grace at
all — it decides purely from the session and the registry, with no import
of `django_mfa.policy`. A billing page gated with `@mfa_required`, and every
admin page once `MFA_PROTECT_ADMIN = True`, requires a factor from every
user who reaches it, cutover or not. See
[Protecting the admin](#protecting-the-admin) below for what that means in
practice.
:::

## What a required user sees

A user `MFA_REQUIRED` applies to, who holds no *primary* factor yet
(`registry.has_primary_factor(user)` is false — see {doc}`api`), is walled to the
security page (`mfa:security_settings`) on every request. The only other pages
reachable are the enroll pages, `mfa:recovery_codes`, and whatever you list in
`MFA_EXEMPT_PATHS`; everything else redirects to the security page with the
original destination recorded in a `next` query parameter. Nothing in django-mfa
reads it back, though: `enroll_factor` redirects unconditionally to
`mfa:recovery_codes` or `mfa:security_settings` once enrollment succeeds, and
`security_settings` never looks at `next` either — so a user does not land back
where they started once they've enrolled. The parameter is there to use if you
build your own post-enrollment redirect on top of these views; it is not honoured
by the ones django-mfa ships.

**Recovery codes alone do not release the wall.** They're exhaustible
(`counts_as_primary_factor = False` — see {doc}`security`), so a required user who
only generates recovery codes is still walled. The same *rule* decides both whether
to *challenge* a user at login and whether the enrollment wall releases them —
recovery codes were never meant to be anyone's sole factor, in either sense. The two
read it through different methods for cost reasons (the login path asks
`registry.primary_enabled_for()`, which returns the adapter list; the wall asks
`registry.has_primary_factor()`, which answers the same question in one query
instead of one per registered adapter), but both derive it from
`Adapter.counts_as_primary_factor`, so they cannot disagree. The wall releases the moment they
enroll `totp`, `webauthn`, or any other adapter with `counts_as_primary_factor =
True` (the default).

:::{warning}
**`MFA_EXEMPT_PATHS` must contain your logout URL for this wall too.** The
enrollment wall is a *second* lockout trap, separate from the one the
pending-verification wall creates: a user required to hold a factor who cannot
enroll one right now — no phone at their desk, no security key issued yet — has no
way out of the redirect loop unless their logout view is exempt. Both walls consult
the same setting; see the warning in {doc}`settings` for the full explanation of
why, and for the exact syntax.
:::

## Per-view enforcement

`MFA_REQUIRED` decides which *users* must hold a factor. `django_mfa.decorators`
decides which *views* require one, for everyone who reaches them — useful when the
requirement is a property of the view itself (a billing flow, an admin action)
rather than of the user asking for it:

    from django_mfa.decorators import mfa_required

    @mfa_required
    def transfer_funds(request):
        ...

For a class-based view, mix in `MfaRequiredMixin` **first**, so its `dispatch()`
runs before the view's own:

    from django.views.generic import FormView
    from django_mfa.decorators import MfaRequiredMixin

    class TransferFundsView(MfaRequiredMixin, FormView):
        ...

Both share the same two *destinations* `MfaMiddleware` redirects to — pending
session → the picker, no primary factor → the security page — and add a third the
middleware doesn't need: unauthenticated → `LOGIN_URL`. `MfaMiddleware` passes an
unauthenticated request straight through, since it isn't a login gate itself; a view
behind only `@mfa_required` may have no other login gate in front of it, so the
decorator supplies that rung on its own.

The no-primary-factor rung is not applied the same way, though. `MfaMiddleware`
only redirects there when **both** `policy.mfa_required_for(user)` is true **and**
the user holds no primary factor — a project with `MFA_REQUIRED = False` (the
default) never reaches that check at all. `@mfa_required`/`MfaRequiredMixin` apply
the no-primary-factor rung unconditionally to anyone who reaches a decorated view,
regardless of `MFA_REQUIRED`: the decorator is itself the policy for that view, not
a mirror of the site-wide one. A view behind `@mfa_required` requires a primary
factor even on a `MFA_REQUIRED = False` project.

## Step-up re-authentication

Adding, removing or regenerating a factor requires a *recent* challenge, not
merely a verified session. A session that verified longer ago than
`MFA_STEPUP_MAX_AGE` (default 300 seconds) is sent back through
`mfa:verify` first. For a safe request (`GET`) it is then returned to the
exact page it asked for. For an unsafe request (`POST`) it is returned to
`mfa:security_settings` instead, or wherever the decorator's own `next_url`
points — the POST body cannot survive the redirect through `mfa:verify`, so
there is nothing to replay; the user re-submits from a page they can act
from.

Without this, a stolen or borrowed session could strip every factor from an
account and enrol its own without presenting anything — and the victim's
password reset would not evict the attacker, because the attacker now holds
a second factor of their own.

Apply it to your own sensitive views:

    from django_mfa.decorators import mfa_recent_required, MfaRecentRequiredMixin

    @mfa_recent_required(max_age=60)
    def transfer_funds(request):
        ...

    class TransferView(MfaRecentRequiredMixin, FormView):
        mfa_stepup_max_age = 60

`mfa_required`/`MfaRequiredMixin` take no configuration at all — `mfa_required`
is a plain decorator with no arguments, and `MfaRequiredMixin` defines no
attributes. `mfa_recent_required`/`MfaRecentRequiredMixin` enforce everything
those two do (pending session, then no-primary-factor) and add a freshness
rung on top, configured with three options neither of the plain forms takes
any of: `max_age` (falls back to `MFA_STEPUP_MAX_AGE` / `mfa_stepup_max_age`
when omitted), `next_url` / `mfa_stepup_next_url`, and `allow_unenrolled` /
`mfa_allow_unenrolled`, **`False` by default**. With the default, a user who
holds no primary factor is redirected to `mfa:security_settings` exactly as
`mfa_required` does — so `@mfa_recent_required(max_age=60)` is never
silently weaker than `@mfa_required`. Pass `allow_unenrolled=True` only for
a view that is itself part of a user's first-enrolment path (as
`enroll_factor` and `recovery_codes` do internally) — such a user has
nothing to re-verify yet, and gating that view would lock them out of the
only pages that could give them a factor. Most host-project views should
leave this at its default.

## Protecting the admin

    MFA_PROTECT_ADMIN = True

is the one-liner: no page on `django.contrib.admin`'s default site
(`django.contrib.admin.site`) is reachable without a verified session. Two
things about it are easy to miss — plus a scope limit worth knowing before
you rely on it, covered in [What is not enforced](#what-is-not-enforced)
below.

**It is enforced by the admin site itself, not by `MfaMiddleware`.**
`django_mfa.admin_site.protect_admin_site()` wraps `admin.site.has_permission()`
and `admin.site.login()` in place, from `DjangoMfaAppConfig.ready()`, whenever
this setting is on — so the gate holds even on a project that never installed
`MfaMiddleware` at all. `has_permission()` refuses an authenticated-but-unverified
staff user outright on every ordinary admin page; `admin:login` is where that
redirect lands (Django's own `AdminSite.admin_view` sends a failed
`has_permission()` there), and the wrapped `login()` checks first whether
this is actually an already-authenticated user rather than rendering the
normal login form for one — if so, it redirects them through `mfa:verify`
(or `mfa:security_settings`, for one holding no primary factor) instead, so
they see the second-factor challenge rather than a login form as though
they'd never signed in. An anonymous visitor is left alone entirely; the
admin's own login form is still the right answer for them.

**It also makes `MFA_REQUIRED` apply to staff — without a second setting.**
`policy.resolve()` unions in `is_staff` whenever `MFA_PROTECT_ADMIN` is on:
whatever `MFA_REQUIRED` is already set to (including its default, `False`)
stays exactly as configured, and any `is_staff` user is *additionally*
required, regardless of whether they match your own predicate. `MFA_PROTECT_ADMIN`
does not rewrite `MFA_REQUIRED` itself — `mfa_status`, `mfa_report` and both
`MfaMiddleware` rungs all go on reading `policy.resolve()` as normal, so
nothing else needs to know the union happened.

That union has a cost worth knowing. Turning `MFA_PROTECT_ADMIN` on makes
`policy.resolve()` non-`None` — even for a project that never set
`MFA_REQUIRED` at all — which activates `MfaMiddleware`'s second rung (the
no-primary-factor wall described above), previously skipped unconditionally
whenever `MFA_REQUIRED` was left at its default. Every authenticated request
now pays `registry.has_primary_factor(request.user)`, one query, to find out
whether it applies. This is deliberate — a staff user with no primary factor
needs to be walled off the *rest* of the site too, not just `/admin/` — but
it is a query every authenticated request now pays that it didn't before.

`MFA_ADMIN_STEPUP = True` goes one step further: with `MFA_PROTECT_ADMIN`
also on, the admin additionally requires a challenge completed within
`MFA_STEPUP_MAX_AGE` (see [Step-up re-authentication](#step-up-re-authentication)
above), not merely a verified session — the same freshness rung
`mfa_recent_required` applies to django-mfa's own factor-mutating views,
applied here to every admin page instead. Set on its own, without
`MFA_PROTECT_ADMIN`, it does nothing at all: nothing reads it unless the
admin site has actually been wrapped. `django_mfa.E011` catches exactly that
misconfiguration at `manage.py check`.

**Grace and `mfa_disable` exemptions do not apply to this gate, at all.**
`MFA_REQUIRED_FROM`/`MFA_GRACE_PERIOD` and `manage.py mfa_disable` both work
by suppressing `policy.mfa_required_for(user)` — a question about *users*,
answered by `django_mfa.policy`. The admin gate is not that question: like
`@mfa_required` (see the warning under [Rolling it out](#rolling-it-out)
above), it is enforced through `decorators.enforcement_state()`, which is
itself the policy for what it gates and is deliberately written to never
import `django_mfa.policy` — grace and exemptions simply don't exist as far
as it's concerned. With `MFA_PROTECT_ADMIN = True`, a staff user holding no
primary factor is walled out of every admin page from the moment it's
deployed — not from your announced cutover, and not once you've run
`mfa_disable` for them. There is no ramp and no exemption for `/admin/`
itself, whatever `MFA_REQUIRED_FROM` or an active `MfaExemption` says about
the rest of the site.

This is a real trap while debugging, because `manage.py mfa_status alice`
reads `policy.mfa_required_for()` — the same question the rest of the site
asks — and will happily print `Required: no`, or `Exempt: <reason>`, or an
"in grace until" line, for a user `/admin/` still refuses outright. Treat
`mfa_status`'s answer as describing `MFA_REQUIRED` only, never as a
prediction of what the admin gate will do once `MFA_PROTECT_ADMIN` is on.

:::{warning}
**The admin's own "Log out" link is not a way out of this gate.** `admin:logout`
is itself an admin URL, rendered through the same `admin_view()` wrapper as
every other admin page — and Django's own `AdminSite.admin_view` special-cases
a failed `has_permission()` on that exact path by redirecting back to
`admin:index` instead of calling `logout()` at all. A staff user who is
walled — pending verification, or required and holding no primary factor yet
— who clicks "Log out" is bounced straight back into the same gate, without
ever actually being logged out.

What gets them out is an ordinary page elsewhere on the site whose logout
view isn't behind an MFA gate — and that only works if `MFA_EXEMPT_PATHS`
contains it, exactly as it already must for the two walls `MfaMiddleware`
enforces (see the warning in {doc}`settings`). `protect_admin_site()` does
not consult `MFA_EXEMPT_PATHS` at all — the admin's own gate has no
exemption mechanism of its own — so this isn't a third set to configure, it's
the same requirement as always: your project's real logout URL, outside
`/admin/`, has to stay reachable to a user any wall has trapped.
:::

## What is not enforced

- **Unauthenticated requests.** Every wall above only applies once
  `request.user.is_authenticated` is true. Your project's own login and
  password-reset flows are still yours to protect — `MFA_REQUIRED` cannot make MFA a
  precondition of authenticating in the first place, only of what an
  already-authenticated session can go on to reach.
- **Step-up re-authentication for your own views.** django-mfa applies
  `mfa_recent_required` to its own three factor-mutating views (see above) but does
  not — cannot — apply it to a view it doesn't know about. If you want a fresh
  challenge before some other sensitive action of your own — say, changing a
  password — apply `mfa_recent_required`/`MfaRecentRequiredMixin` yourself, as shown
  above. See {doc}`security`.
- **A custom `AdminSite` instance, under `MFA_PROTECT_ADMIN`.**
  `protect_admin_site()` only patches `django.contrib.admin.site` — the
  default site. A project that constructs and mounts its **own** `AdminSite`
  instance instead (rather than registering models onto the default one)
  gets **no** protection from `MFA_PROTECT_ADMIN` at all: every page on that
  site is reachable exactly as if the setting were off, with no error or
  warning to say so. `django_mfa.admin_site.MfaAdminMixin` is the answer for
  that case — mix it in ahead of `AdminSite` (or your own subclass of it) to
  get the same `has_permission`/`login` behaviour `protect_admin_site()`
  applies to the default site. See {doc}`settings`, under `MFA_PROTECT_ADMIN`.
