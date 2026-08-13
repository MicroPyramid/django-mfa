import hashlib
import time

from django.contrib.auth.models import User
from django.core import mail
from django.core.cache import cache
from django.core.mail.backends.base import BaseEmailBackend
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import reverse

from django_mfa.adapters.email import (
    ENROLL_STATE_KEY,
    VERIFY_STATE_KEY,
    EmailAdapter,
)
from django_mfa.models import Authenticator
from django_mfa.registry import registry
from django_mfa.utils import mask_email


def request_for(user):
    """A request with a real, mutable session -- the adapter stashes ceremony
    state there, so SessionMiddleware's store is what the tests inspect."""
    from django.contrib.sessions.backends.db import SessionStore

    request = RequestFactory().get("/")
    request.user = user
    request.session = SessionStore()
    return request


def code_from_last_mail(length=6):
    """Pull the ``length``-digit code out of the message body rather than
    reaching into the session, so the test proves the user could actually
    have read it."""
    import re

    match = re.search(rf"\b(\d{{{length}}})\b", mail.outbox[-1].body)
    assert match, f"no code in {mail.outbox[-1].body!r}"
    return match.group(1)


class ExplodingEmailBackend(BaseEmailBackend):
    """A minimal Django email backend that always raises on send.

    Simulates a downstream mail-provider outage without depending on
    smtplib, a real network call, or mocking django.core.mail.send_mail
    (which would test that a mock was called rather than that a real
    failure is handled) -- see review finding 1.
    """

    def send_messages(self, email_messages):
        raise RuntimeError("simulated mail outage")


class MaskEmailTests(TestCase):
    def test_keeps_the_first_and_last_character(self):
        self.assertEqual(mask_email("ashwin@example.com"), "a****n@example.com")

    def test_short_local_parts_are_fully_masked(self):
        self.assertEqual(mask_email("ab@example.com"), "**@example.com")
        self.assertEqual(mask_email("a@example.com"), "*@example.com")

    def test_garbage_in_empty_out(self):
        self.assertEqual(mask_email(""), "")
        self.assertEqual(mask_email("not-an-address"), "")

    def test_a_truthy_non_string_does_not_raise(self):
        """Minor finding 9: `"@" not in address` raises TypeError for a
        truthy non-string. Reachable via otp_tags.py's template filter if a
        host project writes Authenticator.data directly -- that must return
        "" like any other garbage input, not 500 the security page.
        """
        self.assertEqual(mask_email(12345), "")
        self.assertEqual(mask_email(["a@example.com"]), "")
        self.assertEqual(mask_email({"address": "a@example.com"}), "")


class EnrollTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            "ashwin", email="ashwin@example.com", password="pw")
        self.adapter = EmailAdapter()

    def test_begin_sends_a_code_and_masks_the_address(self):
        request = request_for(self.user)
        context = self.adapter.begin_enroll(request)

        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["ashwin@example.com"])
        self.assertEqual(context["address"], "a****n@example.com")

    def test_the_plaintext_code_is_never_stored_in_the_session(self):
        """Under SESSION_ENGINE='signed_cookies' the session round-trips
        through the client. Signed is not encrypted -- a plaintext code there
        is handed straight to the person being challenged."""
        request = request_for(self.user)
        self.adapter.begin_enroll(request)
        code = code_from_last_mail()

        state = request.session[ENROLL_STATE_KEY]
        self.assertNotIn(code, str(state))
        self.assertNotIn(code, str(dict(request.session.items())))
        self.assertIn("hash", state)
        self.assertIn("salt", state)

    def test_the_stored_hash_is_not_reproducible_from_salt_and_code_alone(self):
        """Pins the real property, not just the absence of the literal code.

        A plain, unkeyed sha256(f"{salt}:{code}") would still satisfy the
        test above -- the code isn't a *substring* of that digest -- while
        remaining fully recoverable offline: anyone holding (salt, hash), as
        the challenged user does under SESSION_ENGINE='signed_cookies', can
        just recompute that same digest for all 10**length candidates
        without ever talking to the server, sidestepping both
        MFA_EMAIL_CODE_VALIDITY and MAX_ATTEMPTS (review Critical 1). The
        stored hash must depend on something the client never sees
        (SECRET_KEY, via salted_hmac), so this unkeyed computation must
        *not* match what got stored.
        """
        request = request_for(self.user)
        self.adapter.begin_enroll(request)
        code = code_from_last_mail()

        state = request.session[ENROLL_STATE_KEY]
        offline_guess = hashlib.sha256(
            f"{state['salt']}:{code}".encode()).hexdigest()
        self.assertNotEqual(offline_guess, state["hash"])

    def test_a_correct_code_creates_the_authenticator(self):
        request = request_for(self.user)
        self.adapter.begin_enroll(request)
        authenticator = self.adapter.complete_enroll(
            request, {"code": code_from_last_mail()})

        self.assertEqual(authenticator.type, "email")
        self.assertEqual(authenticator.data["address"], "ashwin@example.com")
        self.assertNotIn(ENROLL_STATE_KEY, request.session)

    def test_a_wrong_code_is_rejected_but_leaves_the_ceremony_open(self):
        request = request_for(self.user)
        self.adapter.begin_enroll(request)

        with self.assertRaises(ValueError):
            self.adapter.complete_enroll(request, {"code": "000000"})

        # Still open: three typos must not cost the user a fresh send, which
        # the send throttle would then refuse.
        authenticator = self.adapter.complete_enroll(
            request, {"code": code_from_last_mail()})
        self.assertEqual(authenticator.type, "email")

    def test_the_ceremony_closes_after_too_many_attempts(self):
        request = request_for(self.user)
        self.adapter.begin_enroll(request)
        for _ in range(3):
            with self.assertRaises(ValueError):
                self.adapter.complete_enroll(request, {"code": "000000"})

        self.assertNotIn(ENROLL_STATE_KEY, request.session)
        with self.assertRaises(ValueError):
            self.adapter.complete_enroll(request, {"code": code_from_last_mail()})

    @override_settings(MFA_EMAIL_CODE_VALIDITY=1)
    def test_an_expired_code_is_rejected(self):
        request = request_for(self.user)
        self.adapter.begin_enroll(request)
        code = code_from_last_mail()
        request.session[ENROLL_STATE_KEY]["issued_at"] = time.time() - 5

        with self.assertRaises(ValueError):
            self.adapter.complete_enroll(request, {"code": code})

    def test_no_address_means_the_factor_is_not_available(self):
        user = User.objects.create_user("noemail", password="pw")
        self.assertFalse(self.adapter.is_available(user))

    def test_begin_enroll_without_an_address_does_not_explode(self):
        """enroll_factor calls begin_enroll outside its try/except, so raising
        here would be a 500 on a hand-typed URL."""
        user = User.objects.create_user("noemail", password="pw")
        context = self.adapter.begin_enroll(request_for(user))
        self.assertIsNone(context["address"])
        self.assertEqual(mail.outbox, [])

    def test_an_at_sign_free_profile_value_is_treated_as_no_address(self):
        """Review finding 7: begin_enroll used to gate on the raw address
        being non-empty, while the template gated on mask_email() being
        non-empty. For a profile email field holding a string with no "@"
        (this package never validates that field), the two disagreed: a
        code was minted and mailed, spending send budget, while the
        rendered page said there was no address and showed no form to type
        the code into at all -- an unrecoverable ceremony every time.
        """
        user = User.objects.create_user(
            "noatsign", email="not-an-address", password="pw")
        context = self.adapter.begin_enroll(request_for(user))
        self.assertIsNone(context["address"])
        self.assertEqual(mail.outbox, [])
        self.assertFalse(self.adapter.is_available(user))


class VerifyTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            "ashwin", email="ashwin@example.com", password="pw")
        self.adapter = EmailAdapter()
        self.authenticator = Authenticator.objects.create(
            user=self.user, type="email",
            data={"address": "enrolled@example.com"})

    def test_the_code_goes_to_the_enrolled_address_not_the_profile_one(self):
        """A factor is possession of a specific mailbox. Following a mutable
        profile field means whoever can change it can redirect the factor."""
        self.adapter.begin_verify(request_for(self.user), self.user)
        self.assertEqual(mail.outbox[0].to, ["enrolled@example.com"])

    def test_the_plaintext_code_is_never_stored_in_the_session(self):
        """Mirror of EnrollTests' test of the same name (review finding 5).
        The enroll-side ceremony proving this was not enough on its own: the
        verify ceremony is the path an attacker who already holds the
        password actually reaches, and it needs this guarantee pinned
        independently rather than inferred from shared helper code -- a
        change that broke it only on the verify side would otherwise pass
        the whole suite.
        """
        request = request_for(self.user)
        self.adapter.begin_verify(request, self.user)
        code = code_from_last_mail()

        state = request.session[VERIFY_STATE_KEY]
        self.assertNotIn(code, str(state))
        self.assertNotIn(code, str(dict(request.session.items())))
        self.assertIn("hash", state)
        self.assertIn("salt", state)

    def test_the_stored_hash_is_not_reproducible_from_salt_and_code_alone(self):
        """Mirror of EnrollTests' test of the same name (Critical 1): the
        verify ceremony is the path an attacker who already holds the
        password actually reaches, so this needs pinning independently
        rather than inferred from shared helper code.
        """
        request = request_for(self.user)
        self.adapter.begin_verify(request, self.user)
        code = code_from_last_mail()

        state = request.session[VERIFY_STATE_KEY]
        offline_guess = hashlib.sha256(
            f"{state['salt']}:{code}".encode()).hexdigest()
        self.assertNotEqual(offline_guess, state["hash"])

    def test_a_correct_code_verifies(self):
        request = request_for(self.user)
        self.adapter.begin_verify(request, self.user)
        result = self.adapter.complete_verify(
            request, self.user, {"code": code_from_last_mail()})
        self.assertTrue(result)

    def test_a_code_cannot_be_replayed(self):
        request = request_for(self.user)
        self.adapter.begin_verify(request, self.user)
        code = code_from_last_mail()
        self.assertTrue(self.adapter.complete_verify(request, self.user,
                                                     {"code": code}))
        self.assertFalse(self.adapter.complete_verify(request, self.user,
                                                      {"code": code}))

    def test_verifying_records_usage(self):
        request = request_for(self.user)
        self.adapter.begin_verify(request, self.user)
        self.adapter.complete_verify(request, self.user,
                                     {"code": code_from_last_mail()})
        self.authenticator.refresh_from_db()
        self.assertIsNotNone(self.authenticator.last_used_at)


class SendThrottleTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            "ashwin", email="ashwin@example.com", password="pw")
        self.adapter = EmailAdapter()
        Authenticator.objects.create(
            user=self.user, type="email", data={"address": "ashwin@example.com"})

    def test_refreshing_the_page_reuses_the_code_and_sends_nothing_more(self):
        request = request_for(self.user)
        self.adapter.begin_verify(request, self.user)
        self.adapter.begin_verify(request, self.user)
        self.adapter.begin_verify(request, self.user)
        self.assertEqual(len(mail.outbox), 1)

    @override_settings(MFA_EMAIL_SEND_RATE_LIMIT="2/5m")
    def test_past_the_limit_no_mail_is_sent_and_nothing_is_revealed(self):
        for _ in range(4):
            request = request_for(self.user)  # a fresh session each time
            context = self.adapter.begin_verify(request, self.user)
            self.assertEqual(context["address"], "a****n@example.com")

        self.assertEqual(len(mail.outbox), 2)

    @override_settings(MFA_EMAIL_SEND_RATE_LIMIT="1/5m")
    def test_the_throttle_is_per_user(self):
        other = User.objects.create_user(
            "other", email="other@example.com", password="pw")
        Authenticator.objects.create(
            user=other, type="email", data={"address": "other@example.com"})

        self.adapter.begin_verify(request_for(self.user), self.user)
        self.adapter.begin_verify(request_for(other), other)

        self.assertEqual(len(mail.outbox), 2)


class SendFailureTests(TestCase):
    """Review finding 1: send_mail's default fail_silently=False meant a
    downstream mail outage propagated straight out of begin_enroll/
    begin_verify -- neither call site is wrapped in a try/except -- as an
    unhandled 500 on every GET of the challenge/enroll page for as long as
    the outage lasted. Worse, the send budget was spent *before* the send
    was attempted, so once MFA_EMAIL_SEND_RATE_LIMIT ran out mid-outage the
    same page started rendering a misleading 200 claiming a code had been
    sent when none ever had -- the one branch that made a throttled send
    distinguishable from a failing one.
    """

    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            "ashwin", email="ashwin@example.com", password="pw")
        self.adapter = EmailAdapter()

    @override_settings(
        EMAIL_BACKEND=(
            "django_mfa.tests.test_adapter_email.ExplodingEmailBackend"))
    def test_a_backend_failure_does_not_raise(self):
        request = request_for(self.user)
        context = self.adapter.begin_enroll(request)  # must not raise

        self.assertEqual(context["address"], "a****n@example.com")
        self.assertEqual(mail.outbox, [])

    @override_settings(
        EMAIL_BACKEND=(
            "django_mfa.tests.test_adapter_email.ExplodingEmailBackend"))
    def test_a_failed_send_leaves_no_usable_ceremony_state(self):
        """The state written just before the failed send must not survive
        it -- otherwise a later complete_enroll() could be tricked into
        validating against a code that was minted but never delivered."""
        request = request_for(self.user)
        self.adapter.begin_enroll(request)

        self.assertNotIn(ENROLL_STATE_KEY, request.session)
        with self.assertRaises(ValueError):
            self.adapter.complete_enroll(request, {"code": "000000"})

    @override_settings(
        EMAIL_BACKEND=(
            "django_mfa.tests.test_adapter_email.ExplodingEmailBackend"))
    def test_verify_side_failure_is_the_same_shape(self):
        Authenticator.objects.create(
            user=self.user, type="email", data={"address": "ashwin@example.com"})
        request = request_for(self.user)
        context = self.adapter.begin_verify(request, self.user)  # must not raise

        self.assertEqual(context["address"], "a****n@example.com")
        self.assertEqual(mail.outbox, [])
        self.assertNotIn(VERIFY_STATE_KEY, request.session)


class ViewIntegrationTests(TestCase):
    """Every other test in this module calls the adapter directly. The
    entire premise of the adapter/registry design is that views/enroll.py
    and views/verify.py drive EmailAdapter completely unmodified -- no
    email-specific view or URL exists -- so at least one test needs to walk
    the real, generic views (review finding 6). This class is also where
    two other findings actually live: the code-length/template maxlength
    mismatch (finding 2) and what three wrong guesses in a row actually do
    once the view's own re-render-on-failure behaviour is in the loop
    (finding 4).

    "email" is registered directly into the production registry singleton
    for the duration of each test, mirroring the registry.unregister() /
    addCleanup(registry.register, ...) pattern test_conf.py's ChecksTests
    and WebAuthnBackendCheckTests already use for WebAuthn: MFA_FACTORS is
    read once at app startup, so override_settings(MFA_FACTORS=...) after
    that has no effect on the already-populated registry.
    """

    def setUp(self):
        cache.clear()
        registry.register(EmailAdapter())
        self.addCleanup(registry.unregister, "email")

        self.user = User.objects.create_user(
            "ashwin", email="ashwin@example.com", password="pw")
        Authenticator.objects.create(
            user=self.user, type="email", data={"address": "ashwin@example.com"})
        self.client = Client()
        self.client.login(username="ashwin", password="pw")

    def test_get_sends_a_code_and_renders_the_default_length(self):
        response = self.client.get(reverse("mfa:verify_factor", args=["email"]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(mail.outbox), 1)
        self.assertContains(response, 'maxlength="6"')

    @override_settings(MFA_EMAIL_CODE_LENGTH=8)
    def test_a_non_default_code_length_is_still_submittable(self):
        """Direct regression test for finding 2: with the template's
        maxlength hardcoded to 6, an 8-digit code could never be typed into
        the input at all -- every submission looked like an ordinary wrong
        code and spent a verify-attempt for nothing.
        """
        response = self.client.get(reverse("mfa:verify_factor", args=["email"]))
        self.assertContains(response, 'maxlength="8"')
        self.assertNotContains(response, 'maxlength="6"')

        code = code_from_last_mail(length=8)
        response = self.client.post(
            reverse("mfa:verify_factor", args=["email"]), {"code": code})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(self.client.session["mfa"]["verified"])

    def test_three_wrong_posts_reuse_then_rotate_in_a_fresh_code(self):
        """Direct regression test for finding 4, and the reason MAX_ATTEMPTS'
        comment was corrected: the cap closes the issued *code*, not the
        guessing session. verify_factor re-renders the challenge page (which
        calls begin_verify again) after every failed POST, so the first two
        wrong guesses are absorbed by the still-open ceremony -- no new mail
        -- and the third, which pops the ceremony state, causes that very
        re-render to mint and mail a fresh code with the attempt counter
        back at zero.
        """
        self.client.get(reverse("mfa:verify_factor", args=["email"]))
        self.assertEqual(len(mail.outbox), 1)

        for _ in range(2):
            response = self.client.post(
                reverse("mfa:verify_factor", args=["email"]), {"code": "000000"})
            self.assertEqual(response.status_code, 400)
        self.assertEqual(len(mail.outbox), 1, "still just the first code")

        response = self.client.post(
            reverse("mfa:verify_factor", args=["email"]), {"code": "000000"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            len(mail.outbox), 2,
            "the third wrong guess closed the ceremony, and the "
            "re-render that follows minted a fresh code")

        # And that fresh code is a live, submittable ceremony -- the cap
        # rotated the code, it didn't lock the factor.
        code = code_from_last_mail()
        response = self.client.post(
            reverse("mfa:verify_factor", args=["email"]), {"code": code})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(self.client.session["mfa"]["verified"])

    def test_security_page_shows_the_bound_address_masked(self):
        """Direct regression test for finding 3: docs/settings.md promises
        the security page shows the enrolled-with address masked, but
        security.html only ever rendered authenticator.name -- always blank
        for email, since complete_enroll never sets it.

        The session is marked verified by hand first: this user already
        holds a primary factor, so login left the session pending, and
        security_settings is not on MfaMiddleware's exempt list (by
        design -- see enrollment_exempt_paths()'s docstring) while pending.
        """
        session = self.client.session
        session["mfa"] = {"verified": True, "method": "email", "at": 0}
        session.save()

        response = self.client.get(reverse("mfa:security_settings"))
        self.assertContains(response, "a****n@example.com")
        self.assertNotContains(response, "ashwin@example.com")

    def test_verify_page_does_not_500_with_no_email_factor_enrolled(self):
        """Minor finding 7: a hand-typed GET /verify/email/ from a user who
        never enrolled the email factor gets begin_verify()'s
        {"address": None} (no `code_length` either -- see begin_verify's
        early return). Without the {% if address %} guard verify_email.html
        mirrors from enroll_email.html, this used to render "We've emailed a
        code to None", maxlength="" and a "-digit code" label instead of
        failing safely.
        """
        User.objects.create_user(
            "noemailfactor", email="noemailfactor@example.com", password="pw")
        client = Client()
        client.login(username="noemailfactor", password="pw")

        response = client.get(reverse("mfa:verify_factor", args=["email"]))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "We&#x27;ve emailed a code to None")
        self.assertNotContains(response, "emailed a code to None")
        self.assertNotContains(response, 'maxlength=""')
        self.assertEqual(mail.outbox, [])


class RegistrationTests(TestCase):
    def test_email_is_not_registered_by_default(self):
        """An existing install must not silently acquire a mail-sending
        factor on upgrade."""
        from django_mfa.conf import DEFAULTS

        self.assertNotIn("email", DEFAULTS["MFA_FACTORS"])

    def test_it_registers_when_asked_for(self):
        from django_mfa.adapters import register_default_adapters
        from django_mfa.registry import Registry

        registry = Registry()
        register_default_adapters(registry, ["totp", "email"])
        self.assertEqual([a.type for a in registry.all()], ["totp", "email"])
