# NOTE: numbered 0007, not 0006 — Task 15 added 0006_mfa_user_handle.py for the
# stored WebAuthn user handle. Depend on that, not on 0005.
#
# UserOTP, UserRecoveryCodes and U2FKey are dropped here. Their data was
# already copied into Authenticator by 0005_migrate_to_authenticator — this
# migration is only safe to apply because that copy already happened.
#
# THIS MIGRATION IS DELIBERATELY IRREVERSIBLE (fix round 1, task 20).
#
# Django's auto-generated reverse for RemoveField/DeleteModel only recreates
# the table SCHEMA — it cannot undo the DROP TABLE and bring back the rows
# that were in it. That sounds like a merely cosmetic gap ("tables come back
# empty") but it is not: a full staged rollback (0007 -> 0006 -> 0005) makes
# it a silent, total-data-loss bug. 0005's reverse() deletes every
# Authenticator row it created (identified by the migrated_from_legacy
# marker) on the assumption that the original UserOTP/UserRecoveryCodes rows
# are "still present and untouched" (see 0005's own docstring) — a promise
# that was true when 0005 was the last-applied migration, but becomes false
# the moment 0007 has ever been applied and then reversed: by the time
# 0005's reverse runs, the legacy tables 0007 dropped have already come back
# EMPTY, not with their original contents. The end state is that every
# user's TOTP secret and both recovery codes are gone from both places
# (Authenticator was cleared by 0005's reverse; UserOTP/UserRecoveryCodes
# never got their rows back), and no step in that sequence raises — the
# operator sees every migration report success.
#
# The `RunPython(RunPython.noop)` operation below has no reverse_code, so
# `Migration.unapply()` refuses to reverse ANY operation in this migration
# and raises IrreversibleError before touching the database — see
# django/db/migrations/migration.py:Migration.unapply(), which validates
# reversibility of every operation in the migration (phase 1) before running
# any of them backwards (phase 2). It forwards as a no-op, so it has zero
# effect on applying this migration normally.
#
# Operator-facing consequence: once this migration has been applied, "roll
# back" cannot mean "run migrate backwards" — the pre-migration TOTP
# secrets/recovery codes (and any never-migrated U2F registrations, per the
# note below) no longer exist anywhere for Django to restore. Rolling back
# means restoring a database backup taken before this migration was applied.
# This should be called out explicitly in the release notes (task 19).
#
# Separately, and independently of the above: U2F registrations were never
# copied onto Authenticator by 0005 in the first place (there is no
# UserOTP/UserRecoveryCodes-style migration path for U2FKey), so they have
# no forward path in this migration set regardless of reversibility.
from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("django_mfa", "0006_mfa_user_handle")]
    operations = [
        migrations.RemoveField(model_name="userrecoverycodes", name="user"),
        migrations.RemoveField(model_name="userotp", name="user"),
        migrations.RemoveField(model_name="u2fkey", name="user"),
        migrations.DeleteModel(name="UserRecoveryCodes"),
        migrations.DeleteModel(name="UserOTP"),
        migrations.DeleteModel(name="U2FKey"),
        # Deliberately irreversible marker — see module docstring above.
        migrations.RunPython(migrations.RunPython.noop, reverse_code=None),
    ]
