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
