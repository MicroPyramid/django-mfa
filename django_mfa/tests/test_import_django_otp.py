import base64
from io import StringIO

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django_otp.oath import TOTP as UpstreamTOTP
from django_otp.plugins.otp_email.models import EmailDevice
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice

from django_mfa import totp as totp_mod
from django_mfa.adapters.email import EmailAdapter
from django_mfa.adapters.recovery_codes import RecoveryCodesAdapter
from django_mfa.crypto import decrypt
from django_mfa.models import Authenticator
from django_mfa.registry import registry

HEX_KEY = "3132333435363738393031323334353637383930"  # b"12345678901234567890"
#: A second, distinct key for tests about two source devices in one run.
OTHER_HEX_KEY = "61" * 20  # b"a" * 20


class ImportDjangoOtpTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("alice", password="pw")

    def _run(self, *args):
        out = StringIO()
        call_command("mfa_import_django_otp", *args, stdout=out)
        return out.getvalue()

    def test_imports_a_confirmed_totp_device(self):
        TOTPDevice.objects.create(user=self.user, key=HEX_KEY, confirmed=True)
        self._run()
        auth = Authenticator.objects.get(
            user=self.user, type=Authenticator.Type.TOTP)
        self.assertEqual(
            decrypt(auth.data["secret"]),
            base64.b32encode(bytes.fromhex(HEX_KEY)).decode())

    def test_imported_secret_matches_django_otp_cross_implementation(self):
        """The real acceptance test for the hex->base32 conversion.

        The previous version of this test compared totp_mod.TOTP(secret).now()
        against totp_mod.TOTP(secret).verify(...) -- both calls into our OWN
        code, which is true for any well-formed base32 secret and proves
        nothing about whether the conversion from django-otp's hex key is
        actually correct (a deliberately wrong conversion, e.g.
        base64.b32encode(HEX_KEY.encode()) -- base32 of the hex ASCII text
        instead of the hex-decoded bytes -- also passes it).

        This instead compares against django-otp's OWN token computation, fed
        the same raw key bytes the import started from (device.bin_key), at a
        time pinned so the comparison can't flake across a 30s window
        boundary the two calls might straddle differently.
        """
        device = TOTPDevice.objects.create(
            user=self.user, key=HEX_KEY, confirmed=True)
        self._run()
        auth = Authenticator.objects.get(
            user=self.user, type=Authenticator.Type.TOTP)
        secret = decrypt(auth.data["secret"])

        fixed_time = 1_700_000_000  # arbitrary Unix timestamp, pinned

        upstream = UpstreamTOTP(device.bin_key)
        upstream.time = fixed_time
        # django_otp's token() returns an unpadded int; django_mfa's own
        # generate_otp() already zero-pads to `digits` characters.
        expected = f"{upstream.token():0{device.digits}d}"

        ours = totp_mod.TOTP(secret).at(fixed_time)

        self.assertEqual(ours, expected)

    def test_skips_unconfirmed_devices(self):
        TOTPDevice.objects.create(user=self.user, key=HEX_KEY, confirmed=False)
        self._run()
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())

    def test_skips_nondefault_digits(self):
        # django_mfa.totp is fixed at 6 digits / 30s / T0=0 / no drift.
        # Importing an 8-digit device would produce a factor whose codes
        # never match -- a silent lockout, the worst possible migration
        # failure.
        TOTPDevice.objects.create(user=self.user, key=HEX_KEY, confirmed=True,
                                  digits=8)
        output = self._run()
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())
        self.assertIn("digits", output)
        self.assertIn("re-enrol", output.lower())

    def test_skips_nondefault_step(self):
        TOTPDevice.objects.create(user=self.user, key=HEX_KEY, confirmed=True,
                                  step=60)
        self._run()
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())

    def test_skips_nondefault_t0(self):
        TOTPDevice.objects.create(user=self.user, key=HEX_KEY, confirmed=True,
                                  t0=1000)
        output = self._run()
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())
        self.assertIn("t0", output)

    def test_skips_nondefault_drift(self):
        # drift is a counter term, not verification-only bookkeeping:
        # django_otp.oath.TOTP.t() computes
        # `((time - t0) // step) + drift` -- a nonzero drift shifts the
        # counter exactly like a nonzero t0 would. It also *accumulates*:
        # TOTPDevice.verify_token() persists a new drift on every successful
        # verification whenever OTP_TOTP_SYNC is on (django-otp's default),
        # so a device with ordinary digits/step/t0 can still carry a
        # nonzero drift purely from a phone clock that runs fast. Importing
        # it without checking drift would "succeed" and then produce codes
        # outside django_mfa's fixed +/-1 step window from the very next
        # login.
        TOTPDevice.objects.create(user=self.user, key=HEX_KEY, confirmed=True,
                                  drift=4)
        output = self._run()
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())
        self.assertIn("drift", output)

    def test_skips_nondefault_tolerance(self):
        # tolerance is TOTPDevice's acceptance-window field -- the number of
        # steps either side of "now" verify_token() will accept
        # (TOTPDevice.verify_token() calls totp.verify(token,
        # self.tolerance, ...)). It defaults to 1, matching django_mfa's own
        # TOTP_VALID_WINDOW = 1, but it is a stored per-device value an
        # operator could have widened -- importing a device with a wider
        # tolerance without checking it would "import clean" today and then
        # silently narrow the window the user is used to, on a source
        # install with OTP_TOTP_SYNC off (so drift never grows to
        # compensate).
        TOTPDevice.objects.create(user=self.user, key=HEX_KEY, confirmed=True,
                                  tolerance=5)
        output = self._run()
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())
        self.assertIn("tolerance", output)

    def test_default_tolerance_device_imports_cleanly(self):
        # Sanity check for the fix above: a device that only differs by NOT
        # differing (tolerance at its default of 1) must still import --
        # confirms SUPPORTED_TOTP's new "tolerance": 1 entry matches
        # TOTPDevice's real default rather than accidentally rejecting every
        # ordinary device.
        TOTPDevice.objects.create(user=self.user, key=HEX_KEY, confirmed=True)
        self._run()
        self.assertTrue(Authenticator.objects.filter(
            user=self.user, type=Authenticator.Type.TOTP).exists())

    def test_imports_static_tokens_as_recovery_codes(self):
        device = StaticDevice.objects.create(user=self.user, name="backup")
        StaticToken.objects.create(device=device, token="aaaa1111")
        StaticToken.objects.create(device=device, token="bbbb2222")
        self._run()
        auth = Authenticator.objects.get(
            user=self.user, type=Authenticator.Type.RECOVERY_CODES)
        self.assertEqual(len(auth.data["codes"]), 2)
        self.assertEqual(auth.data["used"], [])
        # Hashed, not stored plaintext.
        self.assertNotIn("aaaa1111", str(auth.data["codes"]))

    def test_imported_recovery_codes_still_verify(self):
        device = StaticDevice.objects.create(user=self.user, name="backup")
        StaticToken.objects.create(device=device, token="aaaa1111")
        self._run()
        adapter = RecoveryCodesAdapter()
        self.assertTrue(adapter.complete_verify(
            None, self.user, {"code": "aaaa1111"}))

    def test_skips_unconfirmed_static_device(self):
        # StaticDevice inherits `confirmed` from django_otp's abstract
        # Device model exactly as TOTPDevice/EmailDevice do -- an
        # unconfirmed set of backup codes is one the user never finished
        # setting up and must not be imported.
        device = StaticDevice.objects.create(
            user=self.user, name="backup", confirmed=False)
        StaticToken.objects.create(device=device, token="aaaa1111")
        self._run()
        self.assertFalse(Authenticator.objects.filter(
            user=self.user, type=Authenticator.Type.RECOVERY_CODES).exists())

    def test_static_device_with_no_tokens_is_not_imported(self):
        StaticDevice.objects.create(user=self.user, name="backup")
        self._run()
        self.assertFalse(Authenticator.objects.filter(
            user=self.user, type=Authenticator.Type.RECOVERY_CODES).exists())

    def test_imports_confirmed_email_device(self):
        # "email" is off MFA_FACTORS by default (adapters/email.py's own
        # module docstring), so nothing registers an EmailAdapter unless a
        # test opts in -- same pattern test_adapter_email.py uses, since
        # MFA_FACTORS is read once at app startup and
        # override_settings(MFA_FACTORS=...) afterwards has no effect on
        # the already-populated registry.
        registry.register(EmailAdapter())
        self.addCleanup(registry.unregister, "email")
        self.user.email = "alice@example.com"
        self.user.save()
        EmailDevice.objects.create(user=self.user, confirmed=True)
        self._run()
        auth = Authenticator.objects.get(
            user=self.user, type=Authenticator.Type.EMAIL)
        self.assertEqual(auth.data["address"], "alice@example.com")

    def test_email_device_prefers_its_own_address(self):
        registry.register(EmailAdapter())
        self.addCleanup(registry.unregister, "email")
        self.user.email = "alice@example.com"
        self.user.save()
        EmailDevice.objects.create(
            user=self.user, confirmed=True, email="alt@example.com")
        self._run()
        auth = Authenticator.objects.get(
            user=self.user, type=Authenticator.Type.EMAIL)
        self.assertEqual(auth.data["address"], "alt@example.com")

    def test_skips_unconfirmed_email_device(self):
        self.user.email = "alice@example.com"
        self.user.save()
        EmailDevice.objects.create(user=self.user, confirmed=False)
        self._run()
        self.assertFalse(Authenticator.objects.filter(
            user=self.user, type=Authenticator.Type.EMAIL).exists())

    def test_email_device_with_no_address_anywhere_is_skipped(self):
        EmailDevice.objects.create(user=self.user, confirmed=True)
        output = self._run()
        self.assertFalse(Authenticator.objects.filter(
            user=self.user, type=Authenticator.Type.EMAIL).exists())
        self.assertIn("no address", output)

    def test_email_import_skipped_when_adapter_not_registered(self):
        # Default MFA_FACTORS excludes "email". Importing an EmailDevice
        # under that default must not create a row that
        # registry.has_primary_factor(user) can never see -- an inert row
        # that looks like protection to an operator reading the summary but
        # leaves the user bounced to enrolment. This is the scenario the
        # other two "happy path" email tests above deliberately opt out of
        # by registering EmailAdapter themselves.
        self.user.email = "alice@example.com"
        self.user.save()
        EmailDevice.objects.create(user=self.user, confirmed=True)
        output = self._run()
        self.assertFalse(Authenticator.objects.filter(
            user=self.user, type=Authenticator.Type.EMAIL).exists())
        self.assertIn("MFA_FACTORS", output)
        self.assertFalse(registry.has_primary_factor(self.user))

    def test_second_totp_device_in_same_run_is_not_silently_overwritten(self):
        # django-otp puts no uniqueness constraint on Device.user -- two
        # confirmed TOTPDevices for one user is a legal state after a
        # re-enrolment that never cleaned up the old device. With
        # --overwrite and no ordering/dedup, which one "wins" depended on
        # undefined queryset order; the summary also over-counted
        # "imported" against the single row actually left on disk.
        TOTPDevice.objects.create(user=self.user, key=HEX_KEY, confirmed=True)
        TOTPDevice.objects.create(
            user=self.user, key=OTHER_HEX_KEY, confirmed=True)
        output = self._run("--overwrite")
        self.assertEqual(Authenticator.objects.filter(
            user=self.user, type=Authenticator.Type.TOTP).count(), 1)
        auth = Authenticator.objects.get(
            user=self.user, type=Authenticator.Type.TOTP)
        # Deterministic: the lower-pk (first-created) device is the one
        # that's kept.
        self.assertEqual(
            decrypt(auth.data["secret"]),
            base64.b32encode(bytes.fromhex(HEX_KEY)).decode())
        self.assertIn("second", output.lower())

    def test_second_static_device_in_same_run_is_not_silently_overwritten(self):
        device_a = StaticDevice.objects.create(user=self.user, name="a")
        StaticToken.objects.create(device=device_a, token="aaaa1111")
        device_b = StaticDevice.objects.create(user=self.user, name="b")
        StaticToken.objects.create(device=device_b, token="bbbb2222")
        output = self._run("--overwrite")
        self.assertEqual(Authenticator.objects.filter(
            user=self.user, type=Authenticator.Type.RECOVERY_CODES).count(), 1)
        auth = Authenticator.objects.get(
            user=self.user, type=Authenticator.Type.RECOVERY_CODES)
        # device_a's single code survived; device_b's was not silently
        # merged in nor allowed to replace it.
        self.assertEqual(len(auth.data["codes"]), 1)
        self.assertIn("second", output.lower())

    def test_existing_factor_is_skipped_not_replaced(self):
        existing = Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP,
            data={"secret": "untouched"})
        TOTPDevice.objects.create(user=self.user, key=HEX_KEY, confirmed=True)
        output = self._run()
        existing.refresh_from_db()
        self.assertEqual(existing.data["secret"], "untouched")
        self.assertIn("skipped", output.lower())

    def test_overwrite_replaces(self):
        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP,
            data={"secret": "untouched"})
        TOTPDevice.objects.create(user=self.user, key=HEX_KEY, confirmed=True)
        self._run("--overwrite")
        auth = Authenticator.objects.get(user=self.user,
                                         type=Authenticator.Type.TOTP)
        self.assertNotEqual(auth.data["secret"], "untouched")

    def test_dry_run_writes_nothing(self):
        TOTPDevice.objects.create(user=self.user, key=HEX_KEY, confirmed=True)
        output = self._run("--dry-run")
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())
        self.assertIn("1", output)

    def test_dry_run_marks_the_per_row_imported_line_too(self):
        # Not just the summary: an operator reading a real cutover's
        # "imported totp for alice" line has no way to tell it apart from a
        # --dry-run rehearsal's identical line once the summary has scrolled
        # off. Every line printed while nothing is actually being written
        # must say so.
        TOTPDevice.objects.create(user=self.user, key=HEX_KEY, confirmed=True)
        output = self._run("--dry-run")
        imported_line = next(
            line for line in output.splitlines() if "imported totp" in line)
        self.assertIn("[dry run]", imported_line)

    def test_dry_run_marks_the_per_row_skipped_line_too(self):
        TOTPDevice.objects.create(user=self.user, key=HEX_KEY, confirmed=True,
                                  digits=8)
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
        TOTPDevice.objects.create(user=self.user, key=HEX_KEY, confirmed=True)
        self._run("--dry-run", "--overwrite")
        existing.refresh_from_db()
        self.assertEqual(existing.data["secret"], "untouched")

    def test_rerun_is_a_noop(self):
        TOTPDevice.objects.create(user=self.user, key=HEX_KEY, confirmed=True)
        self._run()
        self._run()
        self.assertEqual(Authenticator.objects.filter(
            user=self.user, type=Authenticator.Type.TOTP).count(), 1)

    def test_users_flag_narrows(self):
        other = User.objects.create_user("bob", password="pw")
        TOTPDevice.objects.create(user=self.user, key=HEX_KEY, confirmed=True)
        TOTPDevice.objects.create(user=other, key=HEX_KEY, confirmed=True)
        self._run("--users", "alice")
        self.assertTrue(Authenticator.objects.filter(user=self.user).exists())
        self.assertFalse(Authenticator.objects.filter(user=other).exists())

    def test_emits_no_factor_added(self):
        # A bulk import must not mail every migrated user under
        # MFA_NOTIFY_ON_CHANGE on cutover day.
        from django_mfa import events
        seen = []

        def receiver(sender, **kwargs):
            seen.append(kwargs)

        events.factor_added.connect(receiver)
        try:
            TOTPDevice.objects.create(user=self.user, key=HEX_KEY,
                                      confirmed=True)
            self._run()
        finally:
            # Must disconnect, or this receiver leaks into every later test in
            # the process and silently pollutes their signal assertions.
            events.factor_added.disconnect(receiver)
        self.assertEqual(seen, [])
