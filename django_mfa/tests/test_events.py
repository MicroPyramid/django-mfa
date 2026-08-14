import time

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import Client, TestCase
from django.urls import reverse

from django_mfa import events
from django_mfa import totp as totp_mod
from django_mfa.adapters.recovery_codes import RecoveryCodesAdapter
from django_mfa.adapters.totp import generate_secret
from django_mfa.crypto import encrypt
from django_mfa.models import Authenticator
from django_mfa.registry import registry


class SignalRecorder:
    """Collect every kwargs dict a signal is sent with.

    Connected with a strong reference held by the test, so the receiver is
    not garbage-collected mid-test the way a bare local function would be.
    """

    def __init__(self, signal):
        self.signal = signal
        self.calls = []
        signal.connect(self)

    def __call__(self, sender, **kwargs):
        self.calls.append({"sender": sender, **kwargs})

    def disconnect(self):
        self.signal.disconnect(self)


class EventTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("a@example.com", password="pw")
        self.client = Client()
        self.recorders = []

    def tearDown(self):
        for recorder in self.recorders:
            recorder.disconnect()

    def record(self, signal):
        recorder = SignalRecorder(signal)
        self.recorders.append(recorder)
        return recorder

    def enroll_totp(self):
        secret = generate_secret()
        Authenticator.objects.create(
            user=self.user, type="totp", data={"secret": encrypt(secret)})
        return secret

    def verified_login(self):
        self.client.login(username="a@example.com", password="pw")
        session = self.client.session
        # A recent "at", not 0 -- these tests drive enroll_factor/manage,
        # which now require a fresh challenge (mfa_recent_required), not
        # merely a verified session. See test_stepup.py.
        session["mfa"] = {"verified": True, "method": "totp", "at": int(time.time())}
        session.save()


class FactorAddedTests(EventTestCase):
    def test_enrolling_totp_emits_factor_added(self):
        recorder = self.record(events.factor_added)
        self.client.login(username="a@example.com", password="pw")
        secret = generate_secret()
        response = self.client.post(
            reverse("mfa:enroll_factor", args=["totp"]),
            {"secret_key": secret, "code": totp_mod.TOTP(secret).now()})
        self.assertEqual(response.status_code, 302)

        self.assertEqual(len(recorder.calls), 1)
        call = recorder.calls[0]
        self.assertEqual(call["user"], self.user)
        self.assertEqual(call["authenticator"].type, "totp")
        self.assertIsNotNone(call["request"])

    def test_generating_recovery_codes_emits_factor_added(self):
        self.enroll_totp()
        self.verified_login()
        recorder = self.record(events.factor_added)
        self.client.get(reverse("mfa:recovery_codes"))

        self.assertEqual(len(recorder.calls), 1)
        self.assertEqual(recorder.calls[0]["authenticator"].type, "recovery_codes")

    def test_a_failed_enrollment_emits_nothing(self):
        recorder = self.record(events.factor_added)
        self.client.login(username="a@example.com", password="pw")
        self.client.post(reverse("mfa:enroll_factor", args=["totp"]),
                         {"secret_key": generate_secret(), "code": "000000"})
        self.assertEqual(recorder.calls, [])


class FactorRemovedTests(EventTestCase):
    def test_removal_carries_the_type_and_name_of_the_deleted_row(self):
        auth = Authenticator.objects.create(
            user=self.user, type="webauthn", name="Yubikey 5C", data={})
        self.enroll_totp()
        self.verified_login()
        recorder = self.record(events.factor_removed)

        self.client.post(reverse("mfa:manage"), {"pk": auth.pk})

        self.assertEqual(len(recorder.calls), 1)
        call = recorder.calls[0]
        self.assertEqual(call["factor_type"], "webauthn")
        self.assertEqual(call["name"], "Yubikey 5C")
        self.assertFalse(Authenticator.objects.filter(pk=auth.pk).exists())

    def test_removing_a_row_whose_type_is_no_longer_registered_still_works(self):
        """A row can outlive its adapter's registration -- MFA_FACTORS
        narrowed, or registry.unregister() (the WebAuthn opt-out checks.py
        itself recommends). security_settings lists every row regardless of
        the registry, so removing one of these is a supported action and
        must not 500 after the delete has already committed."""
        adapter = registry.get("webauthn")
        registry.unregister("webauthn")
        self.addCleanup(registry.register, adapter)

        auth = Authenticator.objects.create(
            user=self.user, type="webauthn", name="Orphaned key", data={})
        self.enroll_totp()
        self.verified_login()
        recorder = self.record(events.factor_removed)

        response = self.client.post(reverse("mfa:manage"), {"pk": auth.pk})

        self.assertEqual(response.status_code, 302)
        self.assertFalse(Authenticator.objects.filter(pk=auth.pk).exists())
        self.assertEqual(len(recorder.calls), 1)
        self.assertIsNone(recorder.calls[0]["sender"])


class VerificationTests(EventTestCase):
    def setUp(self):
        super().setUp()
        cache.clear()

    def test_success_emits_mfa_verified(self):
        secret = self.enroll_totp()
        self.client.login(username="a@example.com", password="pw")
        recorder = self.record(events.mfa_verified)

        self.client.post(reverse("mfa:verify_factor", args=["totp"]),
                         {"code": totp_mod.TOTP(secret).now()})

        self.assertEqual(len(recorder.calls), 1)
        self.assertEqual(recorder.calls[0]["method"], "totp")

    def test_wrong_code_emits_mfa_verification_failed(self):
        self.enroll_totp()
        self.client.login(username="a@example.com", password="pw")
        recorder = self.record(events.mfa_verification_failed)

        self.client.post(reverse("mfa:verify_factor", args=["totp"]),
                         {"code": "000000"})

        self.assertEqual(len(recorder.calls), 1)
        self.assertEqual(recorder.calls[0]["method"], "totp")

    def test_missing_field_emits_mfa_verification_failed(self):
        """The caught KeyError path, not just an ordinary wrong code."""
        self.enroll_totp()
        self.client.login(username="a@example.com", password="pw")
        recorder = self.record(events.mfa_verification_failed)

        self.client.post(reverse("mfa:verify_factor", args=["totp"]), {})

        self.assertEqual(len(recorder.calls), 1)

    def test_rate_limited_attempt_still_emits_mfa_verification_failed(self):
        """A refused attempt is exactly what a brute-force detector needs to
        see. It must not change the response, which stays the same generic
        400 a wrong code gets."""
        self.enroll_totp()
        self.client.login(username="a@example.com", password="pw")
        url = reverse("mfa:verify_factor", args=["totp"])
        for _ in range(5):
            self.client.post(url, {"code": "000000"})

        recorder = self.record(events.mfa_verification_failed)
        response = self.client.post(url, {"code": "000000"})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(len(recorder.calls), 1)
        cache.clear()


class RecoveryCodeTests(EventTestCase):
    def test_spending_a_code_reports_how_many_remain(self):
        codes = RecoveryCodesAdapter().generate(self.user)
        self.enroll_totp()
        self.client.login(username="a@example.com", password="pw")
        recorder = self.record(events.recovery_code_used)

        self.client.post(reverse("mfa:verify_factor", args=["recovery_codes"]),
                         {"code": codes[0]})

        self.assertEqual(len(recorder.calls), 1)
        self.assertEqual(recorder.calls[0]["remaining"], 9)


class RobustnessTests(EventTestCase):
    def test_a_raising_receiver_does_not_break_the_view(self):
        """A host project's buggy receiver must never be able to stop a user
        removing an authenticator they believe is compromised. Every
        in-request emission uses send_robust() for exactly this."""
        def boom(sender, **kwargs):
            raise RuntimeError("receiver is broken")

        auth = Authenticator.objects.create(user=self.user, type="webauthn", data={})
        self.enroll_totp()
        self.verified_login()
        events.factor_removed.connect(boom)
        self.addCleanup(events.factor_removed.disconnect, boom)

        response = self.client.post(reverse("mfa:manage"), {"pk": auth.pk})

        self.assertEqual(response.status_code, 302)
        self.assertFalse(Authenticator.objects.filter(pk=auth.pk).exists())
