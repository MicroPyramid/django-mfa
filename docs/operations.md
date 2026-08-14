# Operations

Seven `manage.py` commands for running django-mfa day to day, once it's already
wired into your project: helping a locked-out user, checking rollout
progress, granting a policy exemption, migrating factors in from another
package, and one scheduled housekeeping job. Nothing on this page changes how
django-mfa behaves — see {doc}`enforcement` and {doc}`settings` for that. This
page is about the commands themselves.

Three of the seven — `mfa_status`, `mfa_reset`, `mfa_disable` — take a `user`
argument as **username or pk** (`django_mfa`'s own `resolve_user()` tries
`USERNAME_FIELD` first, then falls back to pk only when the value is all
digits). `mfa_report` and `mfa_prune` take no `user` argument at all — the
first reports across every user, the second is housekeeping. The two importers
take an optional `--users` instead, to narrow an otherwise site-wide run — see
[Migrating from another package](#migrating-from-another-package) below.

None of these commands write to a session directly, but that does **not**
mean their effect always waits for a user's next login — and whether it
does depends on the state of the user's *current* session, not only on
whether `MFA_REQUIRED` applies to them. `MfaMiddleware` checks two separate
walls, in order (see {doc}`enforcement`), and which of them a given session
hits determines the outcome:

**A session already awaiting verification (pending) is hit on its very next
request, regardless of `MFA_REQUIRED` — and, after `mfa_reset`, badly.** The
pending-verification wall runs *before* the enrollment wall below and
applies unconditionally to any authenticated session that hasn't completed
its challenge yet — this is the state a user who is mid-login, or who is
phoning the support desk because they're stuck at the verify screen, is
actually in. It redirects to `mfa:verify`, and once `mfa_reset` has run,
that page has nothing to offer: the picker lists `registry.enabled_for(user)`,
which is now empty, and the template has no `{% empty %}` clause, so the
user sees the picker's heading over an empty list. `mfa:security_settings`
is reachable from the *enrollment* wall's exempt set but not from this one,
so there is no page this session can reach that would let the user
re-enroll. **The only way out is to log out and log back in** — a fresh
login re-evaluates the session against the user's now-empty factor set and
does not mark it pending. If you're resetting a user who is on the phone
mid-login, tell them to log out first, or to expect to have to.

**A session that has already completed a challenge (verified) is affected
only through the enrollment wall, which is conditional on `MFA_REQUIRED`.**
That wall re-evaluates `registry.has_primary_factor(user)` and the
`MFA_REQUIRED` predicate on **every request** an authenticated, verified
user makes, not only at login. For a user `MFA_REQUIRED` currently applies
to, `mfa_reset` (which can drop their factor count to zero) or
`mfa_disable --revoke` (which can restore the requirement) takes effect on
that user's **very next request** — mid-session, with no re-login involved
— and lands them on `mfa:security_settings`, which (unlike the pending case
above) they can actually reach. For a user `MFA_REQUIRED` does not apply
to, there is no wall left to re-evaluate, so the effect genuinely is
deferred: their session stays exactly as verified as it was until they next
log in.

## Inspecting one user

    manage.py mfa_status alice

Read-only. Prints every enrolled factor (type, name for WebAuthn, when it was
added, when it was last used), how many recovery codes remain, whether the
user counts as "protected" (`registry.has_primary_factor()`), whether
`MFA_REQUIRED` applies to them, and whether they hold an active
`MfaExemption`. It never prints `Authenticator.data` — the TOTP secret, the
WebAuthn credential, or the recovery-code hashes — for the same reason
`AuthenticatorAdmin` doesn't (see {doc}`security`).

## Unlocking a user: removing every factor

    manage.py mfa_reset alice

Lists what it's about to delete and asks for confirmation; pass `--yes` to
skip the prompt for scripting. This is the support-desk answer to "I lost my
phone and my recovery codes" — it removes *every* factor (TOTP, WebAuthn,
recovery codes, email) so the user can log in with just their password and
re-enroll from scratch. It leaves any `MfaExemption` alone; resetting factors
and exempting from `MFA_REQUIRED` are independent.

:::{warning}
**If the user's session is already pending verification — e.g. they're the
one on the phone because they're stuck at the verify screen right now —
this command leaves them stuck worse, not unstuck.** `mfa:verify`'s picker
has nothing to offer once every factor is gone, and there is no exempt path
from a pending session to `mfa:security_settings` either. **Tell them to log
out and log back in** before they try again; a fresh login is the only way
their session recovers. See the note above the command list on this page
for the full explanation.

**If `MFA_REQUIRED` applies to this user and their session is already
verified, the effect is immediate — not "next login."** `MfaMiddleware`
re-checks `registry.has_primary_factor(user)` on every request from an
already-authenticated, already-verified session. The moment their factor
count hits zero, their very next request — whatever they're in the middle
of doing — is redirected to `mfa:security_settings` instead of served.
Running this mid-day against a required user interrupts their current
session; it does not wait for them to log back in.
:::

Each row it deletes fires `factor_removed` (`request=None` — see
[Auditing operator actions](#auditing-operator-actions) below), so an audit
receiver sees a support-desk reset exactly as it would see a user removing
their own factor.

## Rollout reporting

    manage.py mfa_report
    manage.py mfa_report --required-only
    manage.py mfa_report --required-only --format csv > outstanding.csv

With no arguments, prints enrolled-factor counts by type, then "Required but
unenrolled" — every user `policy.mfa_required_for()` applies to who does not
hold a primary factor (recovery codes alone don't count; see
{doc}`enforcement`) and does not hold an active `MfaExemption`. `--required-only`
skips the per-type counts. `--format csv` switches the outstanding list to
`pk,<USERNAME_FIELD>` CSV on stdout with nothing else printed ahead of the
header — pipe it straight into a file. It never prints `Authenticator.data`.

## Pruning expired rate-limit counters

    manage.py mfa_prune
    manage.py mfa_prune --quiet          # for cron

With `MFA_RATE_LIMIT_BACKEND = "database"` (the default since 4.5.0), each
rate-limit budget is a row in `RateLimitCounter`. A row stops *counting* the
moment `expires_at` passes — every query filters on it — but nothing deletes it,
because doing that inside a request would put a write on the login path to save
disk. This command is that deletion.

**Schedule it exactly where you schedule `django-admin clearsessions`**, and for
the same reason: neither is required for correctness, both accumulate rows
forever if you skip them. Daily is ample.

    0 4 * * *  manage.py mfa_prune --quiet

It matters slightly more than disk, though. The per-IP budget puts a client
address in `scope`, so the table holds personal data with no purpose beyond its
five-minute window. Pruning is what keeps the retention honest. On
`MFA_RATE_LIMIT_BACKEND = "cache"` there is nothing to prune and the command
says so rather than silently deleting nothing.

## Exempting a user from `MFA_REQUIRED`

    manage.py mfa_disable alice --reason "service account, no interactive login" --until 2099-12-31
    manage.py mfa_disable alice --revoke

`mfa_disable` does **not** remove a user's enrolled factors — that's
`mfa_reset`. It grants (or, with `--revoke`, removes) an `MfaExemption` row,
which suppresses `MFA_REQUIRED` for that one user only. `--reason` is
mandatory when granting: an unexplained permanent exemption from a security
requirement outlives everyone who remembers why it was created. `--until`
(`YYYY-MM-DD`) is optional — omit it for a permanent exemption. Re-running
the command for a user who already has one replaces the reason/expiry rather
than erroring.

An exemption only suppresses the enrollment wall `MFA_REQUIRED` builds. It
does **not** open a view behind `@mfa_required`/`MfaRequiredMixin` — see
{doc}`enforcement` for why the two are deliberately independent.

Granting or revoking fires `mfa_exemption_changed` (`sender` is the
`MfaExemption` model class, not an `Adapter` subclass — there's no adapter
behind an exemption). See {doc}`api` for the full signal reference.

## Migrating from another package

    manage.py mfa_import_django_otp --dry-run
    manage.py mfa_import_django_otp

    manage.py mfa_import_django_mfa2 --dry-run
    manage.py mfa_import_django_mfa2

Run the dry run first: it performs every read exactly as the real run would,
writes nothing (the whole import runs inside one transaction that's rolled
back), and prints the identical summary. Both importers are idempotent —
re-running after a successful import finds the rows already present and
imports nothing new — and neither will replace a factor that already works
unless you pass `--overwrite`. Both also accept `--users alice bob ...` to
limit the run to specific accounts (usernames or pks), useful for a staged
cutover or for retrying just the users a first pass reported as unmatched.

`mfa_import_django_otp` reads `django_otp.plugins.otp_totp.TOTPDevice`,
`otp_static.StaticDevice`/`StaticToken`, and, if installed,
`otp_email.EmailDevice`. **This command also covers
django-two-factor-auth**, which stores its TOTP and static (recovery) tokens
as these same django-otp models — there is nothing two-factor-auth-specific
to run. Its `PhoneDevice` (SMS/call) rows have no counterpart here and are
left untouched.

`mfa_import_django_mfa2` reads `mfa.models.User_Keys`, migrating `TOTP` and
`Email` key types only.

Both importers create rows without emitting `factor_added`, so
`MFA_NOTIFY_ON_CHANGE` will **not** mail every migrated user "a factor was
added" on cutover day — this is a migration of a factor a user already had,
not the addition of a new one. Nothing else about the imported rows is
special: they verify, count toward "protected", and behave exactly like a
factor enrolled through the web UI.

:::{warning}
**Some factors cannot be migrated, and are reported rather than silently
dropped. Read the summary every run — an import that "succeeds" can still
leave specific users unprotected or unable to log in.**

From **either** importer:

- **A factor type with no registered adapter on this install is skipped**,
  naming `MFA_FACTORS` in the message. Email is the common case —
  `MFA_FACTORS` defaults to `["totp", "recovery_codes", "webauthn"]`, so
  email rows are skipped until you add `"email"` to it. Writing the row
  anyway would create an `Authenticator` that looks like protection but
  that nothing on this install will ever offer or verify — the user stays
  bounced to enrollment regardless.
- **A second confirmed/enabled source device of the same type for a user
  who already got one this run is skipped, not merged or overwritten.**
  Neither source package enforces one-device-per-user-per-type, so this is
  a real state after a re-enrollment that never cleaned up its old device.
  The lower-pk (first-created) row wins, deterministically; the discarded
  one is named in the output if it should have won instead.
- **An existing django_mfa factor of the same type is left alone** unless
  you pass `--overwrite`; a working factor is never silently destroyed.

From `mfa_import_django_otp` specifically:

- **Unconfirmed devices are skipped.** A device the user never finished
  setting up (`confirmed=False`) is not a working factor to migrate.
- **A TOTP device using non-default `digits`, `step`, `t0`, *or `drift`* is
  skipped.** `django_mfa` is fixed at 6 digits, a 30-second step, and
  `t0=0`, so an imported 8-digit or 60-second-step device would produce
  codes that never match. **`drift` deserves particular attention**: it's a
  django-otp counter-offset term, not enrollment-time configuration, and it
  *accumulates* — `TOTPDevice.verify_token()` saves a new drift on every
  successful login whenever `OTP_TOTP_SYNC` is on, django-otp's default. A
  user whose phone clock runs fast silently gains drift on every login
  under django-otp and would have logged in without issue indefinitely; a
  nonzero drift is mathematically the same shift as a nonzero `t0`, which
  `django_mfa` cannot represent either. Affected users must re-enroll —
  there is no way to import a device that already needs this
  compensation.

From `mfa_import_django_mfa2` specifically:

- **`FIDO2`, `U2F`, and `Trusted Device` rows have no django_mfa
  counterpart at all** and are reported as such.
- **`RECOVERY` rows are not imported**, even though `recovery_codes` *is* a
  django_mfa factor type — this command's stated scope is TOTP and email
  only, and it reports `RECOVERY` separately from the three above so the
  message doesn't claim "no counterpart" for something that in fact has
  one. Don't read "out of scope" as "not implemented yet, but importable in
  principle": it isn't, for a second and independent reason. django-mfa2
  hashes each recovery code with a hasher class it defines locally in its
  own module (`mfa.recovery.Hash(PBKDF2PasswordHasher)`, `algorithm =
  "pbkdf2_sha256_custom"`, invoked as `make_password(token, salt,
  "pbkdf2_sha256_custom")`), which a django_mfa install has no reason to
  register in `PASSWORD_HASHERS` — `RecoveryCodesAdapter` hashes with
  Django's own default hasher via plain `make_password`/`check_password`.
  Copying those hashes across would produce codes that never verify here
  unless the host project registers a hasher class from the very package
  it's migrating away from. Affected users must generate a fresh set of
  recovery codes from django_mfa's security settings page once they hold a
  primary factor again.
- **The acceptance window narrows, for every migrated TOTP user, and this
  cannot be caught per row.** django-mfa2's own verification
  (`mfa/totp.py`, `valid_window=30`, counted in 30-second ticks) accepts a
  code up to **±15 minutes** out of step; `django_mfa`'s
  `TOTP_VALID_WINDOW = 1` accepts **±30 seconds** — thirty times narrower.
  `User_Keys` records no clock-skew state, so whether any given user's
  device is skewed enough for this to matter cannot be determined from the
  data being migrated. The command prints this warning **unconditionally,
  every run**, not just when it detects a problem, because it cannot
  detect the problem. A user whose phone clock has drifted several minutes
  logged in without trouble under mfa2 and will be silently locked out on
  their first login after cutover, with the summary having said
  "imported". Tell affected users to sync their device clock, or to
  re-enroll if that doesn't fix it — before they file a ticket, not after.
- A row whose `username` matches no user on this install is counted
  separately (`unknown_user`) and reported, not treated as an error —
  django-mfa2 keys rows by username string rather than a foreign key, so a
  stale row is expected, not exceptional.
:::

## Auditing operator actions

`mfa_reset` and `mfa_disable` are the only two of these six commands that
write anything, and both fire the same signals the web UI fires for the
equivalent user-initiated action (`factor_removed`,
`mfa_exemption_changed`) — with one difference worth building a receiver
around: **`request` is `None`**, because there is no request to pass from a
management command. Every signal in `django_mfa.events` documents this as
possible, precisely so a support-desk action still reaches an audit
receiver instead of being the one factor removal or exemption change that
leaves no trace.

**This only covers the command path.** Deleting an `MfaExemption` row
directly in the admin also revokes it (see {doc}`enforcement`'s
"Exempting a user" section), but that path fires no signal at all — Django's
admin has nothing django-mfa listens for on delete. An operator who needs
the deletion to reach whatever is consuming `mfa_exemption_changed` must use
`mfa_disable --revoke` instead of the admin.

A receiver that reaches for `request.META` unconditionally
will raise on this path — since every signal here is sent with
`send_robust()`, that raise is swallowed rather than breaking the command,
but the receiver still won't have logged anything. Write receivers the way
{doc}`api`'s own example does:

    @receiver(factor_removed)
    def audit_factor_removal(sender, user, factor_type, name, request, **kwargs):
        source = request.META.get("REMOTE_ADDR") if request else "console"
        logger.info("factor removed: user=%s type=%s from=%s",
                    user.pk, factor_type, source)

The importers are deliberately the exception: they never emit
`factor_added` at all (see above), so they need no such handling — there is
nothing for a receiver to see from a bulk import in the first place.
