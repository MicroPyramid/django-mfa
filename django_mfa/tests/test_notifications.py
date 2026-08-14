import time
from unittest import mock

from django.contrib.auth.models import User
from django.core import mail
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from django_mfa import events, notifications
from django_mfa.adapters.recovery_codes import RecoveryCodesAdapter
from django_mfa.adapters.totp import generate_secret
from django_mfa.crypto import encrypt
from django_mfa.models import Authenticator


class NotificationTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            "ashwin", email="ashwin@example.com", password="pw")
        self.client = Client()

    def verified_login(self):
        Authenticator.objects.create(
            user=self.user, type="totp",
            data={"secret": encrypt(generate_secret())})
        self.client.login(username="ashwin", password="pw")
        session = self.client.session
        # A recent "at", not 0 -- these tests drive enroll_factor/manage,
        # which now require a fresh challenge (mfa_recent_required), not
        # merely a verified session. See test_stepup.py.
        session["mfa"] = {"verified": True, "method": "totp", "at": int(time.time())}
        session.save()


class OffByDefaultTests(NotificationTestCase):
    def test_nothing_is_sent_by_default(self):
        """An upgrade must not start mailing a host project's users through a
        backend django-mfa doesn't control."""
        self.verified_login()
        self.client.get(reverse("mfa:recovery_codes"))
        self.assertEqual(mail.outbox, [])

    def test_the_signal_still_fires(self):
        """Signals are the always-on half. A project wanting async delivery
        connects its own receiver and leaves MFA_NOTIFY_ON_CHANGE off."""
        calls = []

        def receiver(sender, **kw):
            calls.append(kw)

        # weak=False: Django holds receivers by weak reference by default,
        # and a receiver with no other strong reference can be garbage
        # collected before the signal fires -- making this test pass or fail
        # on GC timing rather than on the behaviour it's checking.
        events.factor_added.connect(receiver, weak=False)
        self.addCleanup(events.factor_added.disconnect, receiver)
        self.verified_login()
        self.client.get(reverse("mfa:recovery_codes"))
        self.assertEqual(len(calls), 1)

    def test_removing_a_factor_does_not_touch_the_registry_when_off(self):
        """Minor finding 6: notify_factor_removed used to call
        registry.primary_enabled_for(user) (3 queries) unconditionally, even
        with MFA_NOTIFY_ON_CHANGE off -- _notify() would immediately discard
        the mfa_disabled context built from it, but the query already ran.
        The early return at the top of the receiver must make a default
        install exactly as cheap as before notifications existed: the
        registry is never even consulted.

        Calls the receiver directly rather than going through mfa:manage:
        that view is now gated by mfa_recent_required (see test_stepup.py),
        which legitimately calls registry.has_primary_factor() itself on
        every request regardless of this setting -- routing through the full
        request would make those two calls indistinguishable from a
        (hypothetical, regressed) call by the receiver this test exists to
        catch.
        """
        with mock.patch(
                "django_mfa.registry.registry.has_primary_factor") as mocked:
            notifications.notify_factor_removed(
                sender=None, user=self.user, factor_type="webauthn",
                name="k")

        mocked.assert_not_called()


@override_settings(MFA_NOTIFY_ON_CHANGE=True,
                   DEFAULT_FROM_EMAIL="security@example.com")
class NotificationContentTests(NotificationTestCase):
    def test_adding_a_factor_notifies(self):
        self.verified_login()
        mail.outbox.clear()
        self.client.get(reverse("mfa:recovery_codes"))

        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(message.to, ["ashwin@example.com"])
        self.assertEqual(message.from_email, "security@example.com")
        self.assertIn("Recovery codes", message.body)

    def test_removing_one_of_two_factors_notifies_removal_only(self):
        self.verified_login()
        extra = Authenticator.objects.create(
            user=self.user, type="webauthn", name="Yubikey", data={})
        mail.outbox.clear()

        self.client.post(reverse("mfa:manage"), {"pk": extra.pk})

        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Yubikey", mail.outbox[0].body)

    def test_removing_the_last_primary_factor_also_says_mfa_is_off(self):
        self.verified_login()
        only = Authenticator.objects.get(user=self.user, type="totp")
        mail.outbox.clear()

        self.client.post(reverse("mfa:manage"), {"pk": only.pk})

        self.assertEqual(len(mail.outbox), 2)
        bodies = " ".join(m.body for m in mail.outbox)
        self.assertIn("no longer", bodies)

    def test_spending_a_recovery_code_reports_the_remaining_count(self):
        codes = RecoveryCodesAdapter().generate(self.user)
        Authenticator.objects.create(
            user=self.user, type="totp",
            data={"secret": encrypt(generate_secret())})
        self.client.login(username="ashwin", password="pw")
        mail.outbox.clear()

        self.client.post(reverse("mfa:verify_factor", args=["recovery_codes"]),
                         {"code": codes[0]})

        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("9", mail.outbox[0].body)

    def test_a_user_with_no_address_is_skipped(self):
        self.user.email = ""
        self.user.save()
        self.verified_login()
        mail.outbox.clear()

        self.client.get(reverse("mfa:recovery_codes"))

        self.assertEqual(mail.outbox, [])


@override_settings(MFA_NOTIFY_ON_CHANGE=True)
class MailFailureTests(NotificationTestCase):
    def test_a_broken_mail_backend_does_not_block_the_security_action(self):
        """Removing a key you believe is compromised is more urgent than the
        notification about it."""
        self.verified_login()
        extra = Authenticator.objects.create(
            user=self.user, type="webauthn", data={})

        with mock.patch("django_mfa.notifications.send_mail",
                        side_effect=OSError("smtp is down")):
            with self.assertLogs("django_mfa.notifications", "ERROR"):
                response = self.client.post(reverse("mfa:manage"),
                                            {"pk": extra.pk})

        self.assertEqual(response.status_code, 302)
        self.assertFalse(Authenticator.objects.filter(pk=extra.pk).exists())
