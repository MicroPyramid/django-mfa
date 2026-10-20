# Operations

django-mfa ships seven `manage.py` commands for running it in production.

## Commands at a glance

| Command | Use it to | Changes data |
|---|---|---|
| [`mfa_status`](#mfa_status) | See one user's factors and whether MFA is required for them | No |
| [`mfa_reset`](#mfa_reset) | Remove every factor from a locked-out user | Yes |
| [`mfa_report`](#mfa_report) | Count enrolled factors and list users who still need one | No |
| [`mfa_disable`](#mfa_disable) | Exempt a user from `MFA_REQUIRED`, or revoke that exemption | Yes |
| [`mfa_import_django_otp`](#mfa_import_django_otp) | Copy factors from django-otp or django-two-factor-auth | Yes |
| [`mfa_import_django_mfa2`](#mfa_import_django_mfa2) | Copy factors from django-mfa2 | Yes |
| [`mfa_prune`](#mfa_prune) | Delete expired rate-limit counters, on a schedule | Yes |

Wherever a command takes a user, pass their username (the field your user model
names in `USERNAME_FIELD`) or their numeric primary key. The username is tried
first, so a numeric username still matches the right person.

## Helping a locked-out user

Start with `mfa_status` to see what the user still has. If they hold unused
recovery codes and can find them, they can sign in with one and you do not need to
change anything. Otherwise, confirm who they are through a channel other than the
account itself, then run `mfa_reset`: afterwards their password alone gets them in.

### `mfa_status`

```bash
python manage.py mfa_status alice
```

Takes one argument, the user. It only reads, and it never prints a TOTP secret,
a WebAuthn credential or recovery-code hashes.

```text
User: alice (pk=42)
  - Recovery codes added 2026-03-02 never used
  - Authenticator app added 2026-03-02 last used 2026-10-19
  - Security key or passkey (YubiKey 5C) added 2026-04-11 never used
Recovery codes remaining: 10
Protected: yes
Required: yes
```

- **Protected** is `yes` when the user holds at least one factor other than
  recovery codes, of a type listed in `MFA_FACTORS`. Recovery codes alone do not
  count.
- **Required** is whether `MFA_REQUIRED` makes the user enroll right now. It reads
  `no` when the setting does not cover them, when they are exempt, and when they
  are still in their grace period. For the last two, one more line says which:
  `In grace until 2026-11-03 (14 days)`, or
  `Exempt: CI deploy bot until 2027-06-30` (`(permanent)` when there is no end
  date).

`Required: no` does not get a user without a factor into `@mfa_required` views or
a protected admin; see [what an exemption does not do](#mfa_disable).

### `mfa_reset`

Removes every factor the user has: authenticator app, security keys and passkeys,
recovery codes and emailed codes.

```bash
python manage.py mfa_reset alice
```

| Option | Effect |
|---|---|
| `user` | Username or pk. |
| `--yes` | Skip the confirmation prompt, for scripts. |

```console
$ python manage.py mfa_reset alice
  - Authenticator app added 2026-03-02 last used 2026-10-19
  - Recovery codes added 2026-03-02 never used
Remove 2 factor(s) from alice? [y/N] y
Removed 2 factor(s) from alice.
```

Any answer other than `y` or `yes` aborts without removing anything. A user with
no factors gets `alice has no factors enrolled; nothing to do.`

**Afterwards, the user can carry on.** If they were stuck on the "Verify it's
you" page, reloading it is enough: with no method left to verify, django-mfa drops
the pending challenge, as a fresh login would never have set it. Nobody asks them
for a code. If `mfa_status` showed `Required: yes`, they land on the security
settings page to enroll; otherwise they can enroll from that page when they
choose.

Also worth knowing:

- A session that had already passed the challenge keeps working. If the user
  shows `Required: yes`, its next page load goes to the security settings page
  instead.
- `mfa_reset` signs nobody out. If the lost device may still be signed in, also
  change the user's password (for example with
  `python manage.py changepassword alice`): Django ends a user's other sessions
  when their password changes.
- A reset does not start a new grace period. Grace is counted from
  `MFA_REQUIRED_FROM` and the user's join date (or your `MFA_GRACE_ANCHOR`), so a
  user already past their deadline must enroll straight away.
- An exemption granted with `mfa_disable` stays in place; the two are
  independent.
- With `MFA_NOTIFY_ON_CHANGE` on, the user gets an email for each removed factor,
  and one saying "Two-factor authentication is off". Warn them so they do not
  take it for an attack.

To remove one factor and keep the rest (for example one lost security key),
delete that row in the Django admin under **Authenticators** instead. That path
sends no signal; see [Auditing operator actions](#auditing-operator-actions).

## Checking rollout progress

### `mfa_report`

```bash
python manage.py mfa_report
python manage.py mfa_report --required-only
python manage.py mfa_report --required-only --format csv > outstanding.csv
```

| Option | Effect |
|---|---|
| `--required-only` | Print only the list of users who still need a factor. |
| `--format {text,csv}` | Default `text`. `csv` prints only the list, header first, ready to redirect to a file. |

```text
Enrolled factors by type:
  recovery_codes: 212
  totp: 187
  webauthn: 64
Required but unenrolled: 2
  - bob (pk=2)
  - dana (pk=3)
```

The counts are factor rows, not users: someone with two security keys counts
twice under `webauthn`.

The list holds every user who has no primary factor (recovery codes alone do not
count), is not exempt, and either must enroll now or is still inside their grace
period. A user in grace has `in grace until YYYY-MM-DD` added to their line.
With `MFA_REQUIRED` off, the list is always empty.

The CSV has the columns `pk`, your `USERNAME_FIELD`, and `grace_until`. That last
one is an ISO 8601 timestamp for a user in grace, and empty for a user who must
enroll now:

```text
pk,username,grace_until
2,bob,2026-11-03T00:00:00+00:00
3,dana,
```

The command checks users one at a time, with a few queries each, so on a large
user table run it outside peak hours.

## Exempting a service account

### `mfa_disable`

An exemption lets one user past the `MFA_REQUIRED` enrollment requirement, for an
account that cannot hold a second factor (a deploy bot, a shared kiosk) or a
person who needs temporary relief.

```bash
python manage.py mfa_disable deploy-bot --reason "CI deploy account, no interactive login" --until 2027-06-30
python manage.py mfa_disable deploy-bot --revoke
```

| Option | Effect |
|---|---|
| `user` | Username or pk. |
| `--reason TEXT` | Required when granting. Stored with the exemption and shown by `mfa_status`. |
| `--until YYYY-MM-DD` | Optional end date. The exemption covers the whole of that day, in your `TIME_ZONE`. A date in the past is refused. Leave it out for a permanent exemption. |
| `--revoke` | Remove the user's exemption. |

```text
deploy-bot is now exempt from MFA_REQUIRED until 2027-06-30: CI deploy account, no interactive login
```

Running it again for a user who already has an exemption replaces the reason and
end date. Granting and revoking both take effect on the user's next request; nobody
needs to log out.

What an exemption does not do:

- **It does not stop the login challenge.** A user who holds a factor is still
  asked for it at every login. For a service account, check that `mfa_status`
  shows `(no factors enrolled)`, and run `mfa_reset` on it if not.
- **It does not open views protected with `@mfa_required` or
  `MfaRequiredMixin`, or the admin when `MFA_PROTECT_ADMIN` is on.** Those send a
  user without a factor to the security settings page whatever their exemption
  says. See {doc}`enforcement`.

Deleting the exemption in the Django admin (**Mfa exemptions**) also revokes it,
but sends no signal. Use `--revoke` when the change must reach your audit log.

## Migrating from another package

The importers copy factors your users already have, so they keep using the same
authenticator app entry. Before you run one:

1. Keep the old package installed, with its apps in `INSTALLED_APPS`. The
   importers read its tables through those apps and stop with an error without
   them.
2. To migrate emailed codes, add `"email"` to `MFA_FACTORS` and configure email
   first (see {doc}`settings`). Otherwise those factors are skipped.
3. Do a dry run and read every `skipped` line before the real run.

```bash
python manage.py mfa_import_django_otp --dry-run
python manage.py mfa_import_django_otp
```

Both importers take the same options:

| Option | Effect |
|---|---|
| `--dry-run` | Run the whole import inside a transaction, then roll it back. Every line starts with `[dry run]`. |
| `--users USER [USER ...]` | Only import these users (usernames or pks). An unknown user stops the command before it imports anything. |
| `--overwrite` | Replace a django-mfa factor of the same type that the user already has. Without it, that user is skipped. |

Running an importer twice is safe: users who already have a factor of that type
are skipped as `already present`. Each run ends with a summary such as
`imported 2, skipped 1 already present, skipped 0 unrepresentable.` Every
`unrepresentable` user will have to enroll again.

A factor type missing from `MFA_FACTORS` is skipped with a message naming the
setting. And because django-mfa holds one authenticator app, one set of recovery
codes and one emailed-code factor per user, a user with two of the same type in
the old package gets only the one with the lower pk; the other is reported as
skipped. If that was the device they use, delete the stale one in the old package
and rerun with `--users` and `--overwrite`.

### `mfa_import_django_otp`

Reads django-otp's TOTP, static-token and email devices. This also covers
django-two-factor-auth, which stores its authenticator app and backup tokens in
those same django-otp tables. Its phone (SMS and call) devices are not imported.

| django-otp device | Becomes | Skipped when |
|---|---|---|
| `TOTPDevice` | Authenticator app | Any of `digits`, `step`, `t0`, `drift` or `tolerance` differs from 6, 30, 0, 0 and 1 |
| `StaticDevice` and its tokens | Recovery codes (the codes the user already has keep working) | The device has no tokens left |
| `EmailDevice` | Emailed code, to the device's own address or else the user's | No address is available, or `"email"` is not in `MFA_FACTORS` |

Unconfirmed devices, and static devices with no tokens left, are ignored without
a message.

Expect some `drift` skips: django-otp adjusts `drift` after each successful login
by default (`OTP_TOTP_SYNC`), so any user whose phone clock runs fast or slow can
have one. Those users must enroll again.

### `mfa_import_django_mfa2`

Reads django-mfa2's enabled `User_Keys` rows.

| `key_type` | Result |
|---|---|
| `TOTP` | Imported as an authenticator app. Skipped if the row has no secret. |
| `Email` | Imported as an emailed code, to the user's own address. Skipped if the user has no email address, or `"email"` is not in `MFA_FACTORS`. |
| `RECOVERY` | Not imported. django-mfa2 hashes recovery codes with its own hasher, so they would never verify here. The user generates new codes from the security settings page. |
| `FIDO2`, `U2F` | Not imported. The user registers their security key or passkey again. |
| `Trusted Device` | Not imported. There is no equivalent. |
| Anything else | Skipped and reported. |

A row whose username matches no user here is left alone and counted separately.

```text
[dry run]   imported totp for carol
[dry run]   skipped carol: FIDO2 has no counterpart in django_mfa; that user must re-enrol.
[dry run]   no user matches 'ghost'; row left alone
note: django-mfa2 accepted codes up to +/-15 minutes out of step (valid_window=30); django_mfa accepts +/-30s. Users with badly-skewed device clocks will need to correct the clock or re-enrol.
[dry run] imported 1, skipped 0 already present, skipped 1 unrepresentable, 1 rows with no matching user.
```

:::{warning}
The `note:` line is printed on every run because the data cannot show who is
affected. django-mfa2 accepted codes up to 15 minutes early or late; django-mfa
accepts 30 seconds either side. A user whose phone clock is a few minutes off
will be rejected after the cutover even though their factor was imported. Before
you switch, tell users to set their phone's clock to update automatically, and to
enroll again if codes are still refused.
:::

### After the import

- Imported factors work exactly like ones enrolled through django-mfa.
- The importers send no `factor_added` signal, so `MFA_NOTIFY_ON_CHANGE` does not
  email every migrated user, and audit receivers see nothing for imported rows.
- Users signed in during the real import who receive an authenticator app or
  emailed-code factor are asked for a code on their next page load. Their
  existing codes work.
- A user who ends up with only recovery codes is not protected. If
  `MFA_REQUIRED` applies to them, `mfa_report` lists them.

## Scheduled housekeeping

### `mfa_prune`

With the default database rate-limit backend (`MFA_RATE_LIMIT_BACKEND =
"database"`), each rate-limit counter is a row that nothing deletes once it
expires. `mfa_prune` deletes them. Nothing breaks without it, but the table grows
forever and keeps client IP addresses (from the per-IP limit) long after they are
needed.

```bash
python manage.py mfa_prune
python manage.py mfa_prune --quiet
```

| Option | Effect |
|---|---|
| `--quiet` | Print nothing. Use it from cron. |

```text
Deleted 14 expired rate-limit counter(s).
```

Schedule it once a day, next to Django's `clearsessions`, which does the same job
for expired sessions:

```text
# crontab
0 4 * * *  cd /srv/myproject && .venv/bin/python manage.py clearsessions
5 4 * * *  cd /srv/myproject && .venv/bin/python manage.py mfa_prune --quiet
```

With `MFA_RATE_LIMIT_BACKEND = "cache"` you do not need it, because cache entries
expire on their own. Running it anyway is harmless; without `--quiet` it prints a
warning saying so.

## Auditing operator actions

Two commands send the same signals as the web pages do, with `request=None`
because there is no request in a management command:

| Command | Signal | Sent | `sender` |
|---|---|---|---|
| `mfa_reset` | `factor_removed` | Once per removed factor, with `user`, `factor_type`, `name`, `request` | The factor's adapter class, or `None` if that type is no longer in `MFA_FACTORS` |
| `mfa_disable` | `mfa_exemption_changed` | Once per grant or revoke, with `user`, `reason`, `expires_at`, `revoked`, `request` (`reason` and `expires_at` are `None` on a revoke) | The `MfaExemption` model |

A receiver that reads `request.META` without checking for `None` raises here. The
command still succeeds (signals are sent with `send_robust()`), but the error is
discarded and nothing is logged. Handle both cases:

```python
# myapp/receivers.py (import this module from your AppConfig.ready())
import logging

from django.dispatch import receiver

from django_mfa.signals import factor_removed, mfa_exemption_changed

logger = logging.getLogger("myapp.security")


def _source(request):
    return request.META.get("REMOTE_ADDR") if request else "manage.py"


@receiver(factor_removed)
def log_factor_removed(sender, user, factor_type, name, request, **kwargs):
    logger.info("factor removed: user=%s type=%s name=%r from=%s",
                user.pk, factor_type, name, _source(request))


@receiver(mfa_exemption_changed)
def log_exemption(sender, user, reason, expires_at, revoked, request, **kwargs):
    logger.info("exemption %s: user=%s reason=%r until=%s from=%s",
                "revoked" if revoked else "granted",
                user.pk, reason, expires_at, _source(request))
```

These operator actions send no signal at all:

- Deleting an exemption in the admin. It does revoke the exemption; use
  `mfa_disable --revoke` instead when the change must be logged.
- Deleting a factor in the admin.
- Running either importer.

See {doc}`api` for the full list of signals and their arguments.
