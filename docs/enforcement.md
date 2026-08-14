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
