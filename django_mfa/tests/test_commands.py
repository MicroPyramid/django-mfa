from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from io import StringIO

from django.contrib.auth.models import User
from django.core.management import CommandError, call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from django_mfa import events
from django_mfa.adapters.recovery_codes import RecoveryCodesAdapter
from django_mfa.crypto import encrypt
from django_mfa.models import Authenticator, MfaExemption
from django_mfa.registry import registry

KNOWN_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
FAKE_CREDENTIAL_ID = "FAKE_CREDENTIAL_ID_MARKER"
FAKE_PUBLIC_KEY = "FAKE_PUBLIC_KEY_MARKER"


class ResolveUserTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("alice", password="pw")

    def test_resolves_by_username(self):
        from django_mfa.management.commands._support import resolve_user
        self.assertEqual(resolve_user("alice"), self.user)

    def test_resolves_by_pk(self):
        from django_mfa.management.commands._support import resolve_user
        self.assertEqual(resolve_user(str(self.user.pk)), self.user)

    def test_username_wins_over_pk(self):
        from django_mfa.management.commands._support import resolve_user
        numeric = User.objects.create_user(str(self.user.pk), password="pw")
        self.assertEqual(resolve_user(str(self.user.pk)), numeric)

    def test_unknown_raises_command_error_naming_both_lookups(self):
        from django_mfa.management.commands._support import resolve_user
        with self.assertRaises(CommandError) as ctx:
            resolve_user("nobody")
        self.assertIn("username", str(ctx.exception))
        self.assertIn("pk", str(ctx.exception))


class MfaStatusTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("alice", password="pw")

    def _run(self, *args):
        out = StringIO()
        call_command("mfa_status", *args, stdout=out)
        return out.getvalue()

    def test_reports_no_factors(self):
        self.assertIn("no factors", self._run("alice").lower())

    def test_lists_a_totp_factor(self):
        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP,
            data={"secret": encrypt(KNOWN_SECRET)})
        output = self._run("alice")
        self.assertIn("Authenticator app", output)

    def test_never_prints_the_secret(self):
        # LOAD-BEARING. Authenticator.data holds the TOTP shared secret, the
        # WebAuthn credential and the recovery-code hashes; a command that
        # printed any of them would reopen the hole AuthenticatorAdmin was
        # hardened to close. Covers all three factor types, not just TOTP --
        # describe_authenticator() must never start formatting per-type
        # detail from `data` for ANY of them, including ones added later.
        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP,
            data={"secret": encrypt(KNOWN_SECRET)})
        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.WEBAUTHN, name="YubiKey",
            data={"credential_id": FAKE_CREDENTIAL_ID,
                  "public_key": FAKE_PUBLIC_KEY, "sign_count": 7})
        RecoveryCodesAdapter().generate(self.user)
        recovery_auth = Authenticator.objects.get(
            user=self.user, type=Authenticator.Type.RECOVERY_CODES)

        output = self._run("alice")

        self.assertNotIn(KNOWN_SECRET, output)
        self.assertNotIn(FAKE_CREDENTIAL_ID, output)
        self.assertNotIn(FAKE_PUBLIC_KEY, output)
        for hashed_code in recovery_auth.data["codes"]:
            self.assertNotIn(hashed_code, output)
        self.assertNotIn("secret", output.lower())

    def test_reports_recovery_codes_remaining(self):
        RecoveryCodesAdapter().generate(self.user)
        self.assertIn("10", self._run("alice"))

    @override_settings(MFA_REQUIRED=True)
    def test_reports_required(self):
        self.assertIn("required: yes", self._run("alice").lower())

    @override_settings(MFA_REQUIRED=True)
    def test_reports_an_active_exemption(self):
        MfaExemption.objects.create(user=self.user, reason="service account")
        output = self._run("alice").lower()
        self.assertIn("exempt", output)
        self.assertIn("service account", output)

    def test_unknown_user_errors(self):
        with self.assertRaises(CommandError):
            self._run("nobody")

    @override_settings(USE_TZ=True, TIME_ZONE="Pacific/Kiritimati")
    def test_authenticator_date_is_formatted_in_the_local_timezone(self):
        # Kiritimati is UTC+14 year-round (no DST), so a late-evening UTC
        # timestamp lands on the *next* calendar date locally. A
        # mid-afternoon UTC timestamp would print the same date whether or
        # not the command actually converts to local time first, so it
        # couldn't discriminate a regression back to a bare strftime on the
        # stored (UTC) value -- this timestamp can.
        created_at = datetime(2024, 1, 1, 23, 0, tzinfo=dt_timezone.utc)
        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP,
            data={"secret": encrypt(KNOWN_SECRET)}, created_at=created_at)
        output = self._run("alice")
        self.assertIn("2024-01-02", output)
        self.assertNotIn("2024-01-01", output)

    @override_settings(USE_TZ=True, TIME_ZONE="Pacific/Kiritimati")
    def test_exemption_until_date_is_formatted_in_the_local_timezone(self):
        # MfaExemption.objects.active_for() only returns rows that are still
        # in force (expires_at in the future), so -- unlike the authenticator
        # date above -- this needs a timestamp computed relative to "now"
        # rather than a fixed past date. Fixing the UTC hour at 23:00 still
        # guarantees the UTC/local dates differ under Kiritimati (UTC+14,
        # no DST): 23:00 UTC + 14h always rolls onto the next calendar date
        # locally, regardless of which future day is chosen.
        expires_at = (timezone.now() + timedelta(days=30)).replace(
            hour=23, minute=0, second=0, microsecond=0)
        MfaExemption.objects.create(
            user=self.user, reason="service account", expires_at=expires_at)
        output = self._run("alice")
        local_date = timezone.localtime(expires_at).date().isoformat()
        utc_date = expires_at.date().isoformat()
        self.assertNotEqual(local_date, utc_date)  # sanity: the two differ
        self.assertIn(local_date, output)
        self.assertNotIn(utc_date, output)


class MfaResetTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("alice", password="pw")
        self.totp = Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP,
            data={"secret": encrypt(KNOWN_SECRET)})
        RecoveryCodesAdapter().generate(self.user)

    def _run(self, *args):
        out = StringIO()
        call_command("mfa_reset", *args, stdout=out)
        return out.getvalue()

    def test_removes_every_factor(self):
        self._run("alice", "--yes")
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())

    def test_emits_factor_removed_per_row(self):
        seen = []

        def receiver(sender, **kwargs):
            seen.append(kwargs)

        events.factor_removed.connect(receiver)
        try:
            self._run("alice", "--yes")
        finally:
            events.factor_removed.disconnect(receiver)

        self.assertEqual(len(seen), 2)
        self.assertEqual({k["factor_type"] for k in seen},
                         {"totp", "recovery_codes"})
        # No request exists in a command. Receivers must tolerate None.
        self.assertTrue(all(k["request"] is None for k in seen))

    def test_a_raising_receiver_does_not_break_the_command(self):
        def boom(sender, **kwargs):
            raise RuntimeError("receiver is broken")

        events.factor_removed.connect(boom)
        try:
            self._run("alice", "--yes")
        finally:
            events.factor_removed.disconnect(boom)
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())

    def test_row_of_an_unregistered_type_still_resets(self):
        # A row can outlive its adapter's registration -- MFA_FACTORS
        # narrowed, or registry.unregister() (the WebAuthn opt-out checks.py
        # itself recommends). Registration only happens once, at app
        # startup (see adapters/__init__.py), so @override_settings cannot
        # simulate a narrowed MFA_FACTORS here -- unregister directly, same
        # as test_events.py's analogous manage_factors test. manage_factors
        # handles this with sender=None; so must the command.
        adapter = registry.get("webauthn")
        registry.unregister("webauthn")
        self.addCleanup(registry.register, adapter)

        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.WEBAUTHN,
            name="old key", data={})
        seen = []

        def receiver(sender, **kwargs):
            seen.append((sender, kwargs["factor_type"]))

        events.factor_removed.connect(receiver)
        try:
            self._run("alice", "--yes")
        finally:
            events.factor_removed.disconnect(receiver)

        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())
        self.assertIn((None, "webauthn"), seen)

    def test_reports_what_it_removed(self):
        self.assertIn("2 factor", self._run("alice", "--yes"))

    def test_leaves_an_exemption_alone(self):
        MfaExemption.objects.create(user=self.user, reason="service account")
        self._run("alice", "--yes")
        self.assertTrue(MfaExemption.objects.filter(user=self.user).exists())

    def test_no_factors_is_not_an_error(self):
        Authenticator.objects.filter(user=self.user).delete()
        self.assertIn("no factors", self._run("alice", "--yes").lower())


class MfaReportTests(TestCase):
    def setUp(self):
        self.enrolled = User.objects.create_user("enrolled", password="pw")
        Authenticator.objects.create(
            user=self.enrolled, type=Authenticator.Type.TOTP,
            data={"secret": encrypt(KNOWN_SECRET)})
        self.bare = User.objects.create_user("bare", password="pw")

    def _run(self, *args):
        out = StringIO()
        call_command("mfa_report", *args, stdout=out)
        return out.getvalue()

    def test_counts_by_type(self):
        output = self._run()
        self.assertIn("totp", output)
        self.assertIn("1", output)

    @override_settings(MFA_REQUIRED=True)
    def test_lists_required_but_unenrolled(self):
        output = self._run("--required-only")
        self.assertIn("bare", output)
        # The user who already holds a factor is not outstanding. Asserted on
        # the --required-only output so the per-type counts (which legitimately
        # mention totp) cannot satisfy or break this.
        self.assertNotIn(f"(pk={self.enrolled.pk})", output)

    @override_settings(MFA_REQUIRED=False)
    def test_nobody_required_when_setting_is_off(self):
        self.assertIn("0", self._run("--required-only"))

    @override_settings(MFA_REQUIRED=True)
    def test_exempt_user_is_not_listed_as_outstanding(self):
        MfaExemption.objects.create(user=self.bare, reason="service account")
        self.assertNotIn("bare", self._run("--required-only"))

    @override_settings(MFA_REQUIRED=True)
    def test_csv_format(self):
        output = self._run("--required-only", "--format", "csv")
        self.assertIn("pk,username", output)
        self.assertIn(f"{self.bare.pk},bare", output)

    @override_settings(MFA_REQUIRED=True)
    def test_csv_format_without_required_only_has_no_leading_prose(self):
        # --format csv is a machine-readable contract on its own -- a
        # consumer piping `mfa_report --format csv > report.csv` must get the
        # header as line one, not two lines of "Enrolled factors by type:"
        # prose ahead of it. Assert on the first line specifically, not a
        # substring: a substring check would pass even with the prose block
        # still printed above the header.
        output = self._run("--format", "csv")
        first_line = output.splitlines()[0]
        self.assertEqual(first_line, "pk,username")

    def test_never_prints_factor_data(self):
        self.assertNotIn(KNOWN_SECRET, self._run())

    @override_settings(MFA_REQUIRED=True)
    def test_recovery_codes_only_user_is_outstanding(self):
        # counts_as_primary_factor = False for recovery codes (they're
        # exhaustible and must never be a user's sole factor), so a user
        # holding only a recovery-codes row is NOT protected and must appear
        # in the outstanding list -- even though a naive
        # `Authenticator.objects.filter(user=user).exists()` check would
        # wrongly treat them as covered because a row exists. This pins the
        # registry.has_primary_factor() call specifically, not just
        # "some check runs".
        recovery_only = User.objects.create_user("recovery_only", password="pw")
        RecoveryCodesAdapter().generate(recovery_only)

        output = self._run("--required-only")

        self.assertIn("recovery_only", output)
        self.assertIn(f"(pk={recovery_only.pk})", output)
