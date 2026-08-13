import os
import subprocess
import sys
import tempfile
import textwrap

from django.contrib.auth.models import User
from django.core.management import call_command
from django.db import connection
from django.db.migrations.exceptions import IrreversibleError
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase

from django_mfa.migrations import _helpers  # created in Step 3
from django_mfa.models import Authenticator

# The migration state just before 0007 drops UserOTP/UserRecoveryCodes/U2FKey.
LEGACY_STATE = [("django_mfa", "0006_mfa_user_handle")]


class DataMigrationTests(TransactionTestCase):
    """Exercises the 0005 forward()/reverse() helpers against the real
    legacy UserOTP/UserRecoveryCodes tables.

    Task 20 deleted the UserOTP/UserRecoveryCodes *model classes* from
    django_mfa/models.py and, via migration 0007, dropped their tables from
    the schema everything else in the suite runs against. 0005 itself never
    imported those classes — it gets its models from the frozen migration
    state via `apps.get_model("django_mfa", "UserOTP")`, which is exactly
    why running the full migration chain from zero still works after the
    classes are gone (see the migrate-from-zero check in the task report).

    Fix round 1 made 0007 deliberately irreversible (see 0007's own
    docstring), so — unlike the first version of this test — the shared
    connection can no longer be walked backwards past 0007 via `migrate`;
    that path now correctly raises IrreversibleError (see
    Migration0007IrreversibleTests below). This test does not attempt that.
    Instead it gets the *historical* UserOTP/UserRecoveryCodes model
    classes from the frozen migration state at LEGACY_STATE (the same
    `apps.get_model` mechanism 0005 itself uses — a pure graph lookup, no
    database access) and creates real, throwaway tables for them directly
    with `schema_editor.create_model()` — the same low-level API Django's
    own CreateModel operation uses internally. This is test-only scratch
    scaffolding, not a rollback of 0007: nothing is recorded in the
    django_migrations table, and the scratch tables are always dropped
    again in addCleanup (which runs even on failure) so later tests see the
    normal, fully migrated schema with no django_mfa_userotp /
    django_mfa_userrecoverycodes tables at all. Authenticator's table is
    untouched by 0006/0007, so the live, importable Authenticator class is
    used directly.
    """

    def setUp(self):
        super().setUp()
        executor = MigrationExecutor(connection)
        historical_apps = executor.loader.project_state(LEGACY_STATE).apps
        self.UserOTP = historical_apps.get_model("django_mfa", "UserOTP")
        self.UserRecoveryCodes = historical_apps.get_model(
            "django_mfa", "UserRecoveryCodes")

        with connection.schema_editor() as schema_editor:
            schema_editor.create_model(self.UserOTP)
            schema_editor.create_model(self.UserRecoveryCodes)
        self.addCleanup(self._drop_legacy_tables)

        self.user = User.objects.create_user("a@example.com", password="pw")
        # user_id=, not user= — self.UserOTP is the *historical* model class
        # (fetched via apps.get_model from the frozen migration state), whose
        # `user` FK points at a distinct historical User class. Assigning the
        # live `self.user` instance directly would raise
        # "must be a User instance"; the plain FK id assignment sidesteps
        # that type check the same way _helpers.forward() does internally
        # (it uses `user_id=otp.user_id`, never `user=`).
        self.otp = self.UserOTP.objects.create(user_id=self.user.pk, otp_type="TOTP",
                                          secret_key="JBSWY3DPEHPK3PXP")
        for code in ("aaaaaaaaaa", "bbbbbbbbbb"):
            self.UserRecoveryCodes.objects.create(user=self.otp, secret_code=code)

    def _drop_legacy_tables(self):
        with connection.schema_editor() as schema_editor:
            # Child (FK to UserOTP) before parent.
            schema_editor.delete_model(self.UserRecoveryCodes)
            schema_editor.delete_model(self.UserOTP)

    def test_forward_creates_totp_authenticator(self):
        _helpers.forward(Authenticator, self.UserOTP, self.UserRecoveryCodes)
        auth = Authenticator.objects.get(user=self.user,
                                         type=Authenticator.Type.TOTP)
        self.assertEqual(auth.data["secret"], "JBSWY3DPEHPK3PXP")

    def test_forward_collapses_recovery_codes_to_one_row(self):
        _helpers.forward(Authenticator, self.UserOTP, self.UserRecoveryCodes)
        auth = Authenticator.objects.get(user=self.user,
                                         type=Authenticator.Type.RECOVERY_CODES)
        self.assertEqual(auth.data["codes"], ["aaaaaaaaaa", "bbbbbbbbbb"])
        self.assertEqual(auth.data["used"], [])
        self.assertTrue(auth.data["migrated_plaintext"])

    def test_user_without_mfa_gets_no_rows(self):
        User.objects.create_user("b@example.com", password="pw")
        _helpers.forward(Authenticator, self.UserOTP, self.UserRecoveryCodes)
        self.assertEqual(Authenticator.objects.filter(
            user__username="b@example.com").count(), 0)

    def test_reverse_removes_copies_and_leaves_legacy_rows_intact(self):
        """Rolling back 0005 must restore the exact pre-0005 state."""
        _helpers.forward(Authenticator, self.UserOTP, self.UserRecoveryCodes)
        self.assertEqual(Authenticator.objects.count(), 2)

        _helpers.reverse(Authenticator)

        self.assertEqual(Authenticator.objects.count(), 0)
        otp = self.UserOTP.objects.get(user_id=self.user.pk)
        self.assertEqual(otp.secret_key, "JBSWY3DPEHPK3PXP")
        self.assertEqual(
            sorted(self.UserRecoveryCodes.objects.values_list(
                "secret_code", flat=True)),
            ["aaaaaaaaaa", "bbbbbbbbbb"],
        )

    def test_migrate_rollback_migrate_again_works(self):
        """The real operator sequence, which the previous reverse() broke."""
        _helpers.forward(Authenticator, self.UserOTP, self.UserRecoveryCodes)
        _helpers.reverse(Authenticator)
        _helpers.forward(Authenticator, self.UserOTP, self.UserRecoveryCodes)

        auth = Authenticator.objects.get(user=self.user,
                                         type=Authenticator.Type.TOTP)
        self.assertEqual(auth.data["secret"], "JBSWY3DPEHPK3PXP")

    def test_reverse_leaves_webauthn_authenticators_alone(self):
        """A passkey registered after 0005 must survive a rollback of 0005."""
        Authenticator.objects.create(user=self.user,
                                     type=Authenticator.Type.WEBAUTHN, name="key")
        _helpers.forward(Authenticator, self.UserOTP, self.UserRecoveryCodes)

        _helpers.reverse(Authenticator)

        self.assertEqual(list(Authenticator.objects.values_list("type", flat=True)),
                         ["webauthn"])

    def test_reverse_leaves_post_cutover_totp_enrollment_alone(self):
        """A TOTP enrolled directly against Authenticator after 0005 ran (no
        legacy UserOTP row backing it) must survive a rollback of 0005 —
        deleting it would silently destroy that user's only MFA factor with
        no legacy row to fall back on."""
        other_user = User.objects.create_user("post_cutover@example.com",
                                              password="pw")
        post_cutover = Authenticator.objects.create(
            user=other_user, type=Authenticator.Type.TOTP,
            data={"secret": "POSTCUTOVERSECRET"},
        )

        _helpers.forward(Authenticator, self.UserOTP, self.UserRecoveryCodes)
        _helpers.reverse(Authenticator)

        remaining = Authenticator.objects.get()
        self.assertEqual(remaining.pk, post_cutover.pk)
        self.assertEqual(remaining.data["secret"], "POSTCUTOVERSECRET")

    def test_forward_totp_with_no_recovery_codes(self):
        """A UserOTP with zero recovery codes must produce a totp row and no
        recovery_codes row at all — regresses the `if codes:` guard."""
        bare_user = User.objects.create_user("no_codes_user@example.com",
                                             password="pw")
        self.UserOTP.objects.create(user_id=bare_user.pk, otp_type="TOTP",
                               secret_key="NOCODESNOCODES12")

        _helpers.forward(Authenticator, self.UserOTP, self.UserRecoveryCodes)

        self.assertTrue(Authenticator.objects.filter(
            user=bare_user, type=Authenticator.Type.TOTP).exists())
        self.assertFalse(Authenticator.objects.filter(
            user=bare_user, type=Authenticator.Type.RECOVERY_CODES).exists())

    def test_forward_preserves_insertion_order_not_alphabetical(self):
        """Codes must preserve insertion (id) order, not sort order — the
        default setUp codes happen to be alphabetical too, which would let an
        `.order_by("secret_code")` regression slip through undetected."""
        self.UserRecoveryCodes.objects.all().delete()
        for code in ("zzzzzzzzzz", "aaaaaaaaaa", "mmmmmmmmmm"):
            self.UserRecoveryCodes.objects.create(user=self.otp, secret_code=code)

        _helpers.forward(Authenticator, self.UserOTP, self.UserRecoveryCodes)

        auth = Authenticator.objects.get(user=self.user,
                                         type=Authenticator.Type.RECOVERY_CODES)
        self.assertEqual(auth.data["codes"],
                         ["zzzzzzzzzz", "aaaaaaaaaa", "mmmmmmmmmm"])


class Migration0007IrreversibleTests(TransactionTestCase):
    """Fix round 1 (task 20): 0007 must not be reversible.

    Django's auto-generated reverse for RemoveField/DeleteModel only
    recreates the table *schema* — it cannot undo the DROP TABLE and bring
    back rows. That looked like a cosmetic gap ("tables come back empty")
    but a full staged rollback (0007 -> 0006 -> 0005) turned it into a
    silent, total-data-loss bug: 0005's reverse() deletes every
    Authenticator row it created (via the migrated_from_legacy marker) on
    the assumption the original UserOTP/UserRecoveryCodes rows are "still
    present and untouched" — true only until 0007 has been applied and then
    reversed. No step in that sequence raised. 0007 now carries a
    `RunPython(RunPython.noop, reverse_code=None)` operation, which has no
    reverse code and is therefore not reversible; `Migration.unapply()`
    checks the reversibility of every operation before running any of them
    backwards, so this blocks the whole migration from being reversed
    without touching the database at all — nothing to clean up here, but
    TransactionTestCase (not TestCase) is used because entering the real
    migration executor's schema_editor to attempt the unapply requires
    toggling SQLite's foreign-key-check pragma, which SQLite refuses to do
    inside an already-open transaction; TestCase wraps every test in one,
    TransactionTestCase does not.
    """

    def test_reversing_0007_raises_irreversible_error(self):
        executor = MigrationExecutor(connection)
        with self.assertRaises(IrreversibleError):
            executor.migrate(LEGACY_STATE)

    def test_makemigrations_check_still_clean(self):
        """Guards against the irreversibility fix itself drifting the
        generated migration state out of sync with models.py. `check=True`
        makes Django raise SystemExit(1) if there are pending changes;
        caught explicitly (SystemExit isn't an Exception, so an uncaught one
        here would abort the whole test run, not just fail this test)."""
        try:
            call_command("makemigrations", "django_mfa", check=True,
                         dry_run=True, verbosity=0)
        except SystemExit as exc:
            self.fail(
                "makemigrations --check reported pending changes after the "
                f"0007 irreversibility fix (exit code {exc.code})")


class Migration0007ForwardFromZeroTests(TestCase):
    """Guards against an over-zealous irreversibility fix breaking the
    forward path: 0001 -> 0007 must still apply cleanly to a brand new,
    empty database.

    Runs in a subprocess against a throwaway sqlite file so it exercises a
    real, from-nothing `migrate`, independent of the shared test database
    (which starts out already migrated to 0007 and — now, by design — can
    never be unapplied past 0007 again within this process).
    """

    SCRIPT = textwrap.dedent("""
        import sys
        import django
        from django.conf import settings

        settings.configure(
            DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3",
                                    "NAME": sys.argv[1]}},
            INSTALLED_APPS=(
                "django.contrib.admin",
                "django.contrib.auth",
                "django.contrib.contenttypes",
                "django.contrib.sessions",
                "django.contrib.messages",
                "django.contrib.staticfiles",
                "django_mfa",
            ),
            ROOT_URLCONF="django_mfa.urls",
            STATIC_URL="/static/",
            SECRET_KEY="test_secret_key",
            MFA_FIDO2_RP_ID="testserver",
        )
        django.setup()

        from django.core.management import call_command
        call_command("migrate", verbosity=0)

        from django.db.migrations.recorder import MigrationRecorder
        applied = {
            name for app, name in MigrationRecorder(
                django.db.connection).applied_migrations()
            if app == "django_mfa"
        }
        print(",".join(sorted(applied)))
    """)

    def test_forward_from_zero_still_applies_through_0007(self):
        import django_mfa
        project_root = os.path.dirname(os.path.dirname(django_mfa.__file__))

        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = os.path.join(tmp_dir, "forward_from_zero.sqlite3")
            result = subprocess.run(
                [sys.executable, "-c", self.SCRIPT, db_path],
                cwd=project_root,
                capture_output=True, text=True,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        applied = set(result.stdout.strip().split(","))
        self.assertEqual(
            applied,
            {
                "0001_initial",
                "0002_auto_20160706_1421",
                "0003_change_secret_code_max_length",
                "0004_authenticator",
                "0005_migrate_to_authenticator",
                "0006_mfa_user_handle",
                "0007_drop_legacy_models",
            },
        )
