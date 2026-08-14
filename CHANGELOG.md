# Changelog

Notable changes to django-mfa, newest first.

This file starts at 4.1.0. For the 2.x/3.x → 4.0 rewrite — which was a
ground-up rebuild with breaking changes to models, URLs, session keys and
settings — see [docs/upgrading.md](docs/upgrading.md); it is far more than a
changelog entry could carry. Releases before 4.1.0 are on the
[GitHub releases page](https://github.com/MicroPyramid/django-mfa/releases).

Versions follow [PEP 440](https://peps.python.org/pep-0440/). The version in
`pyproject.toml` is the only place it is written; the git tag and the GitHub
Release are derived from it (see [docs/contributing.md](docs/contributing.md)).

## 4.4.0

### Added

- **A JSON API**, opt-in via a separate URL include:

      path("api/mfa/", include("django_mfa.api.urls"))

  Every flow the HTML views offer — state, enroll, verify, recovery codes,
  factor removal, passwordless sign-in — as JSON, for an SPA or mobile
  client that renders its own screens. No new dependency: plain Django
  views, so it works inside a DRF, django-ninja or plain-Django project
  alike. Session authentication by default; `MFA_API_AUTHENTICATION`
  (new setting, default `None`) supplies a hook for token or JWT clients.
  Note that **MFA state remains session-backed**, so a client must persist
  the session cookie — see [docs/rest_api.md](docs/rest_api.md), which is
  explicit about what that rules out.
- **System check `django_mfa.E006`**, rejecting an unimportable or
  non-callable `MFA_API_AUTHENTICATION`, the way `E004` already does for
  `MFA_REQUIRED`.
- **Passkey autofill (WebAuthn conditional mediation)**, opt-in per form
  with `data-conditional="true"` plus `autocomplete="username webauthn"` on
  your username input. Offers a returning user their passkey from the
  browser's own dropdown instead of behind a button. Off by default because
  it moves `mfa:passkey_begin` to once per login-page view for every
  anonymous visitor, and that endpoint writes a session — see
  [docs/recipes.md](docs/recipes.md).
- **`tools/compile_catalogs.py`**, which refreshes catalog source
  references and compiles every `.mo`. It is `makemessages` + `msgfmt` in
  pure Python, because gettext's binaries are not a dependency this project
  imposes — including on its own CI.
- The sandbox login page now demonstrates passkey sign-in, including
  autofill. It previously demonstrated neither.

### Changed

- **The six translations are now live.** `de`, `es`, `fr`, `pt_BR`, `ja`
  and `zh_Hans` shipped in 4.3.0 with every entry marked `fuzzy`, which
  meant users still saw English. Every entry is now translated and
  unfuzzed, and compiled `.mo` files ship — Django reads only those, so
  without them the catalogs did nothing. They remain machine-drafted and
  maintainer-reviewed rather than reviewed by a native speaker; corrections
  are welcome. See [docs/translations.md](docs/translations.md).
- The order of operations for an enrollment or verification attempt moved
  to `django_mfa.flows`, and the enforcement rungs to
  `decorators.enforcement_state`/`recent_enforcement_state`. Both are
  shared verbatim by the HTML views and the API, so the two cannot come to
  apply different rules. No behaviour change — this is why the HTML views
  are shorter in this release.

### Fixed

- **`"Remove"` was rendering in `django.contrib.admin`'s words, not ours,
  in every language admin translates.** gettext keys on the string itself
  and Django merges all installed apps' catalogs, with the app listed
  *first* in `INSTALLED_APPS` winning a shared key — and admin is listed
  first in nearly every project. The button now carries a
  `context "second-factor method"`, which makes the key ours alone, and a
  test fails on any bare msgid a bundled Django app also translates.
- The "managed by your organization" message shown when
  `MFA_OWNED_BY_ENTERPRISE` blocks a removal was the one user-facing string
  never wrapped for translation.

## 4.3.0

### Added

- **Translation catalogs.** `django_mfa/locale/` now ships `django.pot` (75
  entries) and machine-drafted `.po` files for `de`, `es`, `fr`, `pt_BR`,
  `ja` and `zh_Hans`. Every entry is marked `fuzzy`, so gettext ignores it
  and users still see English: **no language is live yet**, and a draft only
  starts appearing after a human reviews it and removes the flags. See
  [docs/translations.md](docs/translations.md). No compiled `.mo` files
  ship, because a fully fuzzy catalog compiles to an empty one.
- The Python side is now translatable, matching the templates (which already
  were): the verification error, the passkey sign-in error, each adapter's
  `verbose_name`, and `Authenticator.Type`'s labels. Wrapping the `Type`
  labels needs **no migration** — a `gettext_lazy` proxy compares equal to
  the string it wraps, so the autodetector sees no change to `choices`
  (verified on Django 4.2, 5.2 and 6.1).

- **Django 6.1 support**, now claimed in the classifiers and exercised in CI
  on Python 3.12 and 3.13. Django 6.x requires Python 3.12+, so the matrix
  excludes it on 3.10/3.11; those interpreters keep Django 4.2 and 5.2, both
  still LTS. No source change was needed — the suite already passed on 6.x.
  (Django 6.0 passes too, but is not claimed or tested.)

### Changed

- The PyPI classifier is now `Development Status :: 5 - Production/Stable`,
  up from `4 - Beta`.
- `publish.yml`'s pre-release smoke matrix now tests the newest supported
  corner as Python 3.13 + Django 6.1, up from 3.13 + 5.2. The oldest corner
  (3.10 + 4.2) is unchanged.

### Fixed

- `.gitignore`'s blanket `*.pot`/`*.mo` rules excluded the package's own
  catalogs. Because hatchling honours `.gitignore` at build time, an ignored
  catalog is also an unshipped one — Django would find no locale directory
  in the installed package and silently fall back to English. Negations now
  keep `django_mfa/locale/` tracked, and `test_packaging.py` asserts the
  catalogs are in the built wheel.

## 4.2.0

### Added

- **Step-up re-authentication.** `mfa_recent_required`/`MfaRecentRequiredMixin`
  (`django_mfa.decorators`) and `MFA_STEPUP_MAX_AGE` (default `300` seconds)
  require a *recent* challenge, not merely a verified session, before a
  factor can be added, removed or regenerated. Set `MFA_STEPUP_MAX_AGE =
  None` to switch it off for django-mfa's own three built-in views (they
  never pass their own `max_age`, so they fall back to the setting) and
  restore 4.1.0 behaviour there. It does **not** override a host view's own
  explicit `@mfa_recent_required(max_age=60)` — an explicit per-view
  `max_age` always wins over the global setting, by design. See
  [docs/enforcement.md](docs/enforcement.md).
- **Four management commands** for day-to-day operation:
  `mfa_status` (read-only — one user's enrolled factors and MFA status),
  `mfa_reset` (remove every factor from a locked-out user so they can
  re-enroll), `mfa_report` (rollout coverage, and who `MFA_REQUIRED` applies
  to but who hasn't enrolled — text or CSV), and `mfa_disable` (grant or
  `--revoke` an `MfaExemption` from `MFA_REQUIRED` for one user; does not
  touch that user's enrolled factors). See
  [docs/operations.md](docs/operations.md).
- **Two importers** for migrating factors in from another package:
  `mfa_import_django_otp` (also covers **django-two-factor-auth**, which
  stores its TOTP and static tokens as django-otp rows) and
  `mfa_import_django_mfa2`. Both support `--dry-run`, `--users`, and
  `--overwrite`, are idempotent, and never destroy a working factor unless
  `--overwrite` is passed. See
  [docs/operations.md](docs/operations.md#migrating-from-another-package) for
  what each does and does not migrate — several factor shapes (a
  clock-drifted django-otp TOTP device, django-mfa2's wider acceptance
  window, `RECOVERY` rows, and any factor type absent from `MFA_FACTORS`) are
  reported rather than imported, and are worth reading before a cutover.
- **`MfaExemption`** model and manager (`MfaExemption.objects.active_for()`),
  and the **`mfa_exemption_changed`** signal (`user`, `reason`, `expires_at`,
  `revoked`, `request`) it fires. Written only by `mfa_disable` — there is no
  web UI for granting yourself an exemption from a security requirement.
- **System check `django_mfa.E005`**, rejecting an `MFA_STEPUP_MAX_AGE` that
  isn't a positive integer or `None`, the same way `E004` already does for
  `MFA_REQUIRED`.

### Changed

- **Behaviour change.** Adding, removing or regenerating a factor now
  requires a session that completed a challenge within the last
  `MFA_STEPUP_MAX_AGE` seconds (default 300), not merely a verified one.
  Set `MFA_STEPUP_MAX_AGE = None` to restore 4.1.0 behaviour for
  django-mfa's own views (see the Added entry above for the one case this
  doesn't cover). This is the one place this release does not upgrade to
  byte-identical behaviour by default — see
  [docs/upgrading.md](docs/upgrading.md).
- **`MFA_REMEMBER_MY_BROWSER` now interacts with step-up.** A trusted
  browser still skips the challenge at *login* exactly as before — the RMB
  cookie check marks the session verified immediately — but that session is
  only fresh the moment it's created. `MFA_STEPUP_MAX_AGE` is enforced on
  every factor change regardless of how the session became verified, so a
  trusted browser that adds, removes or regenerates a factor more than
  `MFA_STEPUP_MAX_AGE` seconds after logging in is now challenged for that
  action — the RMB cookie is consulted only at login, not re-checked by the
  step-up gate. This is a visible change for installs that enabled RMB
  specifically to avoid challenges. See
  [docs/settings.md](docs/settings.md).
- **Signals may now carry `request=None`.** `mfa_reset` and `mfa_disable`
  emit `factor_removed`/`mfa_exemption_changed` from outside any request, so
  that an operator action is exactly as auditable as the equivalent
  user-initiated one. A receiver that reaches for `request.META`
  unconditionally must be updated to tolerate `None` first — see
  [docs/api.md](docs/api.md)'s Signals section.
- The verification picker now honours `?next=`, so a single-factor user is
  returned to the page they requested after logging in rather than to
  `LOGIN_REDIRECT_URL`.

### Upgrading

Run `manage.py migrate django_mfa`. Migration `0009_mfa_exemption` adds the
`MfaExemption` table; it is reversible.

Nothing else is required to keep 4.1.0 behaviour, with one exception: factor
changes are gated on `MFA_STEPUP_MAX_AGE` by default (see above). Set it to
`None` if you need the previous, unconditional behaviour immediately after
upgrading.

## 4.1.0

Three additions, all opt-in. **An install that sets none of the new settings
behaves identically to 4.0.1** — the only required step is running the new
migration.

### Added

- **`MFA_REQUIRED` — require a second factor.** Until now enrollment was
  entirely voluntary: the middleware only challenged users who had *already*
  enrolled, so anyone who never opted in was never prompted, and there was no
  way to require MFA of staff. Accepts `False` (default), `True`, a callable
  taking a user, or a dotted path to one; `django_mfa.policy` supplies
  `is_staff` and `in_groups(*names)`. A required user holding no primary factor
  is walled to the security page — only the enroll pages, recovery codes and
  `MFA_EXEMPT_PATHS` stay reachable — until they enroll. See
  [docs/enforcement.md](docs/enforcement.md).
- **`@mfa_required` and `MfaRequiredMixin`** (`django_mfa.decorators`) for
  per-view enforcement regardless of `MFA_REQUIRED`. The setting picks users,
  the decorator picks views, and neither can express the other.
- **System check `django_mfa.E004`**, rejecting an unimportable or
  non-callable `MFA_REQUIRED` at `manage.py check` rather than from inside
  middleware on a user's first live request. Unlike E001–E003 it is not gated
  on WebAuthn being active.
- **An emailed one-time-code factor** (`"email"`) — the only built-in that does
  not assume the user still holds a device they enrolled earlier, which makes
  it the lost-phone path. **Not in the `MFA_FACTORS` default**: add it
  explicitly, so that upgrading cannot silently acquire a factor that sends
  mail through a backend this package does not control. New settings
  `MFA_EMAIL_CODE_LENGTH` (6), `MFA_EMAIL_CODE_VALIDITY` (300s),
  `MFA_EMAIL_SEND_RATE_LIMIT` (`"3/5m"`), `MFA_EMAIL_SUBJECT`, and
  `MFA_FROM_EMAIL`.
- **Five signals** — `factor_added`, `factor_removed`, `mfa_verified`,
  `mfa_verification_failed`, `recovery_code_used` — importable from
  `django_mfa.signals`, always on. All sent with `send_robust()`, so a raising
  receiver cannot break a security action such as removing a compromised key.
  `mfa_verification_failed` also fires for attempts the rate limiter refuses: a
  brute-force detector needs the refused attempts, not only the evaluated ones.
  See [docs/api.md](docs/api.md).
- **`MFA_NOTIFY_ON_CHANGE`** (default `False`) — emails the user when a factor
  is added or removed, when a recovery code is spent, and when their last
  factor goes. Sending is synchronous and best-effort: a failure is logged,
  never raised, because a mail outage must not turn "remove this key I think is
  compromised" into a 500. For async delivery or non-email routing, connect
  your own receiver to the signals above and leave this off — that is why the
  signals ship independently of the emails.
- **`Registry.has_primary_factor(user)`** — the boolean form of
  `primary_enabled_for()` in one query instead of one per registered adapter.
  Both derive from `Adapter.counts_as_primary_factor`, so they cannot disagree.
- New documentation page, **Enforcement**.

### Changed

- `Adapter.complete_enroll()` **must return the created `Authenticator`**. This
  was always true of the built-ins, but it is now a documented contract: the
  `factor_added` signal carries the return value, so a custom adapter returning
  `None` silently degrades every host project's audit trail for that factor
  type.
- `ratelimit.parse/check/record_failure` gained a `setting=` keyword argument so
  a second budget (emailed-code sends) can be counted against its own setting.
  Existing positional calls are unaffected; `record_failure` is now an alias of
  the more general `record`.
- `docs/custom_factors.md`'s worked example is now a printed-backup-token
  factor. Its previous example was an emailed-code factor, which now ships as a
  built-in, so the page had begun documenting how to reimplement something the
  package provides.

### Upgrading

Run `manage.py migrate django_mfa`. Migration `0008_email_factor` adds the
`email` factor type and extends the `mfa_one_singleton_authenticator_per_user`
constraint to cover it — a singleton factor missing from that condition would
not actually be constrained. Unlike `0007`, it is reversible.

Nothing else is required. `MFA_REQUIRED`, `MFA_NOTIFY_ON_CHANGE` and the
absence of `"email"` from `MFA_FACTORS`'s default are what keep existing
behaviour unchanged.
