from io import StringIO

import pyotp
from django.contrib.auth.models import User
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.test import TestCase, override_settings
from mfa.models import User_Keys

from django_mfa import totp as totp_mod
from django_mfa.adapters.email import EmailAdapter
from django_mfa.crypto import decrypt
from django_mfa.management.commands.mfa_import_django_mfa2 import Command
from django_mfa.models import Authenticator
from django_mfa.registry import registry

SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
#: A second, distinct secret for tests about two source rows in one run.
OTHER_SECRET = "KRSXG5CTMVRXEZLUKN2XAZLSEBBHK5A="


class ImportDjangoMfa2Tests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("alice", password="pw")

    def _run(self, *args):
        out = StringIO()
        call_command("mfa_import_django_mfa2", *args, stdout=out)
        return out.getvalue()

    # --- TOTP ---------------------------------------------------------

    def test_imports_totp(self):
        User_Keys.objects.create(
            username=self.user.username, key_type="TOTP", enabled=True,
            properties={"secret_key": SECRET})
        self._run()
        auth = Authenticator.objects.get(user=self.user,
                                         type=Authenticator.Type.TOTP)
        self.assertEqual(decrypt(auth.data["secret"]), SECRET)

    def test_imported_secret_matches_pyotp_cross_implementation(self):
        """The real acceptance test for the "no conversion needed" claim.

        Unlike mfa_import_django_otp (hex -> base32), this command performs
        NO transformation on the secret: mfa2's own `properties["secret_key"]`
        is already base32 (pyotp.random_base32() writes it -- see
        mfa/totp.py's getToken), the exact format django_mfa's own
        otp.OTP.byte_secret() expects. Proven two ways here: the stored
        value round-trips byte-identical (checked by test_imports_totp via
        decrypt()), and an independent pyotp instance fed the same secret
        produces the identical code django_mfa's own TOTP does, at a time
        pinned so the two calls can't straddle a 30s window boundary
        differently.
        """
        User_Keys.objects.create(
            username=self.user.username, key_type="TOTP", enabled=True,
            properties={"secret_key": SECRET})
        self._run()
        auth = Authenticator.objects.get(user=self.user,
                                         type=Authenticator.Type.TOTP)
        secret = decrypt(auth.data["secret"])
        self.assertEqual(secret, SECRET)  # byte-identical; no conversion

        fixed_time = 1_700_000_000  # arbitrary Unix timestamp, pinned
        expected = pyotp.TOTP(SECRET).at(fixed_time)
        ours = totp_mod.TOTP(secret).at(fixed_time)
        self.assertEqual(ours, expected)

    @override_settings(MFA_SECRET_ENCRYPTION_KEYS=["k"])
    def test_totp_secret_is_actually_encrypted(self):
        """Pins that the command genuinely calls encrypt(), not just that
        the stored value round-trips through decrypt().

        crypto.encrypt() is a no-op unless MFA_SECRET_ENCRYPTION_KEYS is
        set, and the test settings baseline (test_runner.py) doesn't set
        it -- so test_imports_totp alone would pass identically whether the
        command called encrypt(secret) or just stored the raw secret
        directly. With a key configured here, encrypt() actually transforms
        the value, so the stored blob must differ from the plaintext and
        still decrypt back to it.
        """
        User_Keys.objects.create(
            username=self.user.username, key_type="TOTP", enabled=True,
            properties={"secret_key": SECRET})
        self._run()
        auth = Authenticator.objects.get(user=self.user,
                                         type=Authenticator.Type.TOTP)
        self.assertNotEqual(auth.data["secret"], SECRET)
        self.assertEqual(decrypt(auth.data["secret"]), SECRET)

    def test_reports_acceptance_window_mismatch_unconditionally(self):
        # mfa2's own verification (mfa/totp.py:24) accepts codes up to
        # +/-15 minutes out of step; django_mfa accepts +/-30s. No per-row
        # check can catch this (User_Keys stores no clock-skew state at
        # all), so it must be printed every run, even one that imports
        # nothing.
        output = self._run()
        self.assertIn("valid_window=30", output)
        self.assertIn("+/-30s", output)

    def test_skips_disabled_keys(self):
        User_Keys.objects.create(
            username=self.user.username, key_type="TOTP", enabled=False,
            properties={"secret_key": SECRET})
        self._run()
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())

    def test_missing_secret_is_skipped(self):
        User_Keys.objects.create(
            username=self.user.username, key_type="TOTP", enabled=True,
            properties={})
        self._run()
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())

    def test_second_totp_key_in_same_run_is_not_silently_overwritten(self):
        # django-mfa2 puts no uniqueness constraint on User_Keys -- two
        # enabled TOTP rows for one user is a legal state after a
        # re-enrolment that never disabled/removed the old key. With
        # --overwrite and no ordering/dedup, which one "wins" would depend
        # on undefined queryset order, and the summary would over-count
        # "imported" against the single row actually left on disk.
        User_Keys.objects.create(
            username=self.user.username, key_type="TOTP", enabled=True,
            properties={"secret_key": SECRET})
        User_Keys.objects.create(
            username=self.user.username, key_type="TOTP", enabled=True,
            properties={"secret_key": OTHER_SECRET})
        output = self._run("--overwrite")
        self.assertEqual(Authenticator.objects.filter(
            user=self.user, type=Authenticator.Type.TOTP).count(), 1)
        auth = Authenticator.objects.get(user=self.user,
                                         type=Authenticator.Type.TOTP)
        # Deterministic: the lower-pk (first-created) row is the one kept.
        self.assertEqual(decrypt(auth.data["secret"]), SECRET)
        self.assertIn("second", output.lower())

    # --- Email ----------------------------------------------------------

    def test_imports_email(self):
        # "email" is off MFA_FACTORS by default (adapters/email.py's own
        # module docstring), so nothing registers an EmailAdapter unless a
        # test opts in -- same pattern test_import_django_otp.py and
        # test_adapter_email.py use, since MFA_FACTORS is read once at app
        # startup and override_settings() afterwards has no effect on the
        # already-populated registry.
        registry.register(EmailAdapter())
        self.addCleanup(registry.unregister, "email")
        self.user.email = "alice@example.com"
        self.user.save()
        User_Keys.objects.create(
            username=self.user.username, key_type="Email", enabled=True,
            properties={})
        self._run()
        auth = Authenticator.objects.get(user=self.user,
                                         type=Authenticator.Type.EMAIL)
        self.assertEqual(auth.data["address"], self.user.email)

    def test_email_with_no_address_on_file_is_skipped(self):
        # mfa2 stores no per-key address for an Email row (Email.py's start
        # view never sets `properties`); sendEmail() always targets the
        # account's own user.email. If that's blank there is nothing to
        # migrate -- and writing a factor with a blank address would make
        # registry.has_primary_factor(user) True while
        # EmailAdapter.is_available() stays False, i.e. "protected" but
        # never actually verifiable.
        registry.register(EmailAdapter())
        self.addCleanup(registry.unregister, "email")
        User_Keys.objects.create(
            username=self.user.username, key_type="Email", enabled=True,
            properties={})
        output = self._run()
        self.assertFalse(Authenticator.objects.filter(
            user=self.user, type=Authenticator.Type.EMAIL).exists())
        self.assertIn("no email address", output)

    def test_email_import_skipped_when_adapter_not_registered(self):
        # Default MFA_FACTORS excludes "email". Importing under that default
        # must not create a row that registry.has_primary_factor(user) can
        # never see -- an inert row that looks like protection to an
        # operator reading the summary but leaves the user bounced to
        # enrolment.
        self.user.email = "alice@example.com"
        self.user.save()
        User_Keys.objects.create(
            username=self.user.username, key_type="Email", enabled=True,
            properties={})
        output = self._run()
        self.assertFalse(Authenticator.objects.filter(
            user=self.user, type=Authenticator.Type.EMAIL).exists())
        self.assertIn("MFA_FACTORS", output)

    # --- key_types with no counterpart / out of scope --------------------

    def test_reports_fido2_as_unmigratable(self):
        User_Keys.objects.create(
            username=self.user.username, key_type="FIDO2", enabled=True,
            properties={"device": {}})
        output = self._run()
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())
        self.assertIn("FIDO2", output)

    def test_reports_u2f_as_unmigratable(self):
        User_Keys.objects.create(
            username=self.user.username, key_type="U2F", enabled=True,
            properties={})
        output = self._run()
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())
        self.assertIn("U2F", output)

    def test_reports_trusted_device_as_unmigratable(self):
        # User_Keys.save() has a special case for this key_type: when no
        # "signature" is already present it builds one via
        # jwt.encode({..., "key": self.properties["key"]}, ...), so an empty
        # properties dict raises KeyError before the row can even be
        # created. The brief's own sample test used properties={}, which
        # does not survive against the real, installed model.
        User_Keys.objects.create(
            username=self.user.username, key_type="Trusted Device",
            enabled=True, properties={"key": "irrelevant-to-this-test"})
        self.assertIn("Trusted Device", self._run())

    def test_reports_recovery_as_out_of_scope(self):
        # RECOVERY is real (mfa/recovery.py) and DOES have a django_mfa
        # counterpart (recovery_codes) -- unlike FIDO2/U2F/Trusted Device,
        # which have none at all. The brief this command was written from
        # omitted RECOVERY entirely; converting it is out of this command's
        # stated scope (TOTP + email only), so it must be reported with a
        # message that doesn't falsely claim "no counterpart".
        User_Keys.objects.create(
            username=self.user.username, key_type="RECOVERY", enabled=True,
            properties={"secret_keys": ["somehash"], "salt": "abc"})
        output = self._run()
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())
        self.assertIn("RECOVERY", output)
        self.assertNotIn("no counterpart", output)

    def test_unrecognised_key_type_is_skipped(self):
        User_Keys.objects.create(
            username=self.user.username, key_type="Bogus", enabled=True,
            properties={})
        output = self._run()
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())
        self.assertIn("Bogus", output)

    # --- username-keyed rows ---------------------------------------------

    def test_unknown_username_is_reported_not_fatal(self):
        User_Keys.objects.create(
            username="ghost", key_type="TOTP", enabled=True,
            properties={"secret_key": SECRET})
        output = self._run()
        self.assertIn("ghost", output)

    def test_username_field_lookup_is_tried_before_the_literal_fallback(self):
        # On the default user model USERNAME_FIELD == "username", so this
        # is exercising the *first* branch of _find_user -- the direct
        # lookup succeeds and the literal-username fallback is never
        # reached. See FindUserFallbackTests below for the fallback branch
        # itself, which needs a field that differs from "username" to
        # exercise at all (not available from a real end-to-end run in
        # this suite -- AUTH_USER_MODEL is not swapped here).
        User_Keys.objects.create(
            username=self.user.username, key_type="TOTP", enabled=True,
            properties={"secret_key": SECRET})
        self._run()
        self.assertTrue(Authenticator.objects.filter(user=self.user).exists())

    def test_users_flag_narrows(self):
        other = User.objects.create_user("bob", password="pw")
        User_Keys.objects.create(
            username=self.user.username, key_type="TOTP", enabled=True,
            properties={"secret_key": SECRET})
        User_Keys.objects.create(
            username=other.username, key_type="TOTP", enabled=True,
            properties={"secret_key": OTHER_SECRET})
        self._run("--users", "alice")
        self.assertTrue(Authenticator.objects.filter(user=self.user).exists())
        self.assertFalse(Authenticator.objects.filter(user=other).exists())

    # --- existing factor / overwrite --------------------------------------

    def test_existing_factor_is_skipped_not_replaced(self):
        existing = Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP,
            data={"secret": "untouched"})
        User_Keys.objects.create(
            username=self.user.username, key_type="TOTP", enabled=True,
            properties={"secret_key": SECRET})
        output = self._run()
        existing.refresh_from_db()
        self.assertEqual(existing.data["secret"], "untouched")
        self.assertIn("skipped", output.lower())

    def test_overwrite_replaces(self):
        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP,
            data={"secret": "untouched"})
        User_Keys.objects.create(
            username=self.user.username, key_type="TOTP", enabled=True,
            properties={"secret_key": SECRET})
        self._run("--overwrite")
        auth = Authenticator.objects.get(user=self.user,
                                         type=Authenticator.Type.TOTP)
        self.assertEqual(decrypt(auth.data["secret"]), SECRET)

    # --- dry-run ------------------------------------------------------

    def test_dry_run_writes_nothing(self):
        User_Keys.objects.create(
            username=self.user.username, key_type="TOTP", enabled=True,
            properties={"secret_key": SECRET})
        output = self._run("--dry-run")
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())
        self.assertIn("1", output)

    def test_dry_run_marks_the_per_row_imported_line_too(self):
        # Not just the summary: an operator reading a real cutover's
        # "imported totp for alice" line has no way to tell it apart from a
        # --dry-run rehearsal's identical line once the summary has scrolled
        # off. Every line printed while nothing is actually being written
        # must say so.
        User_Keys.objects.create(
            username=self.user.username, key_type="TOTP", enabled=True,
            properties={"secret_key": SECRET})
        output = self._run("--dry-run")
        imported_line = next(
            line for line in output.splitlines() if "imported totp" in line)
        self.assertIn("[dry run]", imported_line)

    def test_dry_run_marks_the_per_row_skipped_line_too(self):
        User_Keys.objects.create(
            username=self.user.username, key_type="FIDO2", enabled=True)
        output = self._run("--dry-run")
        skipped_line = next(
            line for line in output.splitlines() if "skipped" in line)
        self.assertIn("[dry run]", skipped_line)

    def test_dry_run_overwrite_does_not_destroy_existing_factor(self):
        # The one path where a bug would destroy a working factor: a
        # --dry-run that (correctly) decides to overwrite must still not
        # actually write anything.
        existing = Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP,
            data={"secret": "untouched"})
        User_Keys.objects.create(
            username=self.user.username, key_type="TOTP", enabled=True,
            properties={"secret_key": SECRET})
        self._run("--dry-run", "--overwrite")
        existing.refresh_from_db()
        self.assertEqual(existing.data["secret"], "untouched")

    def test_rerun_is_a_noop(self):
        User_Keys.objects.create(
            username=self.user.username, key_type="TOTP", enabled=True,
            properties={"secret_key": SECRET})
        self._run()
        self._run()
        self.assertEqual(Authenticator.objects.filter(
            user=self.user, type=Authenticator.Type.TOTP).count(), 1)

    # --- signals ------------------------------------------------------

    def test_emits_no_factor_added(self):
        # A bulk import must not mail every migrated user under
        # MFA_NOTIFY_ON_CHANGE on cutover day.
        from django_mfa import events
        seen = []

        def receiver(sender, **kwargs):
            seen.append(kwargs)

        events.factor_added.connect(receiver)
        try:
            User_Keys.objects.create(
                username=self.user.username, key_type="TOTP", enabled=True,
                properties={"secret_key": SECRET})
            self._run()
        finally:
            # Must disconnect, or this receiver leaks into every later test
            # in the process and silently pollutes their signal assertions.
            events.factor_added.disconnect(receiver)
        self.assertEqual(seen, [])

    # --- absent source -----------------------------------------------

    def test_missing_mfa2_raises_clean_command_error(self):
        from django.core.management import CommandError as CE

        from django_mfa.management.commands import mfa_import_django_mfa2 as cmd_mod

        original = cmd_mod._get_model
        cmd_mod._get_model = lambda: None
        try:
            with self.assertRaises(CE):
                call_command("mfa_import_django_mfa2")
        finally:
            cmd_mod._get_model = original


class FindUserFallbackTests(TestCase):
    """Unit tests for Command._find_user(), the fix for SHOULD FIX 5.

    django-mfa2 is not internally consistent about what it writes into
    User_Keys.username -- USERNAME_FIELD from one Email.py write site,
    a literal `username` attribute from every other site including all of
    TOTP (see the module docstring). On this suite's user model
    USERNAME_FIELD == "username", so a real end-to-end command run can
    never actually exercise the mismatch -- AUTH_USER_MODEL is not swapped
    anywhere in this test suite, and standing one up is out of scope for
    this fix. These tests call _find_user() directly with a `field` that
    deliberately differs from "username", using django.contrib.contenttypes
    .ContentType (already installed, not the real user model, but any model
    works for exercising this method's pure lookup-and-fallback logic)
    standing in for "a user model whose USERNAME_FIELD isn't literally
    'username'".
    """

    def setUp(self):
        self.command = Command()
        self.ct = ContentType.objects.create(
            app_label="a-distinctive-label", model="widget")

    def test_prefers_the_named_field_when_it_matches(self):
        found = self.command._find_user(
            ContentType, "app_label", "a-distinctive-label")
        self.assertEqual(found, self.ct)

    def test_falls_back_to_literal_username_when_the_field_lookup_misses(self):
        # ContentType has no "username" field at all, so the fallback branch
        # needs a model that has one -- reuse the real user model, but with
        # a `field` ("email") that deliberately does NOT hold the value the
        # source row stored. alice's email is blank (create_user doesn't
        # set one), so the direct "email" lookup misses and only the
        # literal-`username` fallback can find her.
        alice = User.objects.create_user("alice", password="pw")
        found = self.command._find_user(User, "email", "alice")
        self.assertEqual(found, alice)

    def test_prefers_the_named_field_over_the_fallback_when_both_could_match(self):
        # Two different users: one whose USERNAME_FIELD-analogue ("email"
        # here) is "shared-value", another whose literal `username` is
        # "shared-value". The named-field lookup must win -- it is tried
        # first and is correct for a row written by Email.py's enrolment
        # path.
        field_match = User.objects.create_user(
            "field-match", email="shared-value", password="pw")
        User.objects.create_user("shared-value", password="pw")
        found = self.command._find_user(User, "email", "shared-value")
        self.assertEqual(found, field_match)

    def test_returns_none_when_neither_the_field_nor_username_matches(self):
        found = self.command._find_user(User, "email", "nobody-at-all")
        self.assertIsNone(found)

    def test_field_error_from_a_model_with_no_username_field_is_swallowed(self):
        # ContentType has neither "username" nor any value equal to this
        # bogus app_label, so the primary lookup misses and the fallback's
        # own `.filter(username=...)` raises FieldError (no such field) --
        # this must return None, not propagate.
        found = self.command._find_user(
            ContentType, "app_label", "no-such-label")
        self.assertIsNone(found)

    def test_default_field_never_reaches_the_fallback(self):
        # field == "username" is the default-user-model case (this
        # project's own test suite runs under it end to end): the fallback
        # branch is unreachable because it's the same lookup already tried.
        alice = User.objects.create_user("alice", password="pw")
        found = self.command._find_user(User, "username", "alice")
        self.assertEqual(found, alice)
