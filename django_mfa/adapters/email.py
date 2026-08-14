"""A one-time code delivered by email.

The only factor here that does not assume the user still holds a device they
enrolled earlier, which makes it the "lost my phone" path. It is an ordinary
enrolled factor: the user opts in, confirms a code, and gets an Authenticator
row they can see and remove like any other.

NOT in the MFA_FACTORS default. An existing install must not silently acquire
a factor that sends mail through a backend this package does not control.
"""

import logging
import secrets
import time

from django.conf import settings as django_settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.crypto import salted_hmac
from django.utils.translation import gettext_lazy as _

from django_mfa import ratelimit
from django_mfa.conf import settings as mfa_settings
from django_mfa.models import Authenticator
from django_mfa.registry import Adapter
from django_mfa.utils import mask_email, strings_equal, user_email

logger = logging.getLogger(__name__)

#: Ceremony state keys. Separate for enrollment and verification for the same
#: reason webauthn.py keeps AUTH_STATE_KEY and PASSKEY_STATE_KEY apart: a code
#: issued to confirm a new address must not be spendable as a challenge
#: answer, or vice versa.
ENROLL_STATE_KEY = "django_mfa_email_enroll"
VERIFY_STATE_KEY = "django_mfa_email_verify"

#: Rate-limit scope for *sending*, distinct from the per-factor verification
#: budget. Colon-namespaced so it cannot collide with a factor type, which is
#: a URL segment and never contains one.
SEND_SCOPE = "email:send"
SEND_SETTING = "MFA_EMAIL_SEND_RATE_LIMIT"

#: Wrong guesses allowed against one issued *code* before that code is
#: discarded and a fresh one is required on the next begin_enroll/
#: begin_verify call. Not zero: closing on the first typo would force that
#: next call to mint a resend for an ordinary fumble-fingered digit, instead
#: of just re-checking the same still-good code.
#:
#: This bounds brute-forcing of one issued code -- it does NOT by itself end
#: a guessing session. views/verify.py (and enroll.py) re-call begin_verify/
#: begin_enroll to re-render the challenge page after every failed POST, and
#: once this cap pops the ceremony state, that very call sees no state left,
#: mints a fresh code, and mails it -- attempts reset to zero (see
#: _ensure_code). What actually bounds an attacker across repeated
#: rotations like that is the pair of rate limits: MFA_VERIFY_RATE_LIMIT
#: (wrong POSTs per user+factor) and MFA_EMAIL_SEND_RATE_LIMIT (fresh codes
#: minted per user) -- either one running out stops the run. Do not read
#: this constant as "the ceremony locks after N attempts"; only those two
#: settings make that true.
MAX_ATTEMPTS = 3


def _issue_code():
    length = mfa_settings.MFA_EMAIL_CODE_LENGTH
    return f"{secrets.randbelow(10 ** length):0{length}d}"


def _hash(code, salt):
    """Key a code's stored digest off SECRET_KEY, so the session itself can't
    be used to recover it.

    The session is not a safe place for the plaintext: under
    SESSION_ENGINE="django.contrib.sessions.backends.signed_cookies" it
    round-trips through the client, and signed is not encrypted -- the payload
    is readable base64. But hashing alone doesn't fix that if the hash is a
    plain, unkeyed digest of ``(salt, code)``: both salt and digest sit in
    that same readable session, so the same client that receives them can
    recompute sha256(f"{salt}:{code}") for all 10**length candidates entirely
    offline, with no server round-trip to rate-limit or a validity window to
    race -- a single-threaded pure-Python loop clears a 6-digit space in a
    fraction of a second. MFA_EMAIL_CODE_VALIDITY and MAX_ATTEMPTS only bind
    guesses made *against the server*; they do nothing once the attacker has
    a local copy of the digest and can check candidates without it.

    salted_hmac() closes that: it mixes in settings.SECRET_KEY, a value the
    client never sees, so the digest is unforgeable without it -- there is no
    offline computation the holder of (salt, digest) alone can run. The
    per-issue salt is kept anyway, as HMAC's "key_salt" input, so two codes
    issued to the same user never hash identically. One consequence worth
    knowing: rotating SECRET_KEY invalidates every in-flight code, since the
    HMAC output changes with it -- harmless at this construction's 300s TTL,
    but worth knowing before you're debugging it during a key rotation.
    """
    return salted_hmac(salt, code, algorithm="sha256").hexdigest()


def _is_fresh(state):
    return (time.time() - state.get("issued_at", 0)
            < mfa_settings.MFA_EMAIL_CODE_VALIDITY)


class EmailAdapter(Adapter):
    type = Authenticator.Type.EMAIL
    verbose_name = _("Emailed code")
    supports_multiple = False
    supports_enroll = True
    counts_as_primary_factor = True

    # --- availability ------------------------------------------------------

    def is_available(self, user):
        """Offering a factor that cannot possibly deliver is worse than not
        offering it, so an account with no address never sees this one.

        Gated on mask_email() rather than a bare truthiness check on
        user_email() -- the same predicate begin_enroll/begin_verify use to
        decide whether to show the code-entry form. A profile field holding
        a string with no "@" in it (never validated by this package) used to
        pass the old truthiness check, so a code was minted and mailed
        against it while the template's own `{% if address %}` -- fed by
        mask_email(), which returns "" for exactly that input -- refused to
        render anything to type it into. One predicate, used everywhere,
        keeps "deliverable" and "displayable" from disagreeing.
        """
        if not mask_email(user_email(user)):
            return False
        return super().is_available(user)

    # --- sending -----------------------------------------------------------

    def _send(self, user, address, code):
        context = {
            "code": code,
            "user": user,
            "validity_minutes": max(
                1, mfa_settings.MFA_EMAIL_CODE_VALIDITY // 60),
        }
        subject = mfa_settings.MFA_EMAIL_SUBJECT or render_to_string(
            "django_mfa/email/otp_code_subject.txt", context)
        # A subject with a newline in it is a header-injection vector; a
        # template file almost always ends with one.
        subject = " ".join(subject.split())
        body = render_to_string("django_mfa/email/otp_code.txt", context)
        send_mail(
            subject, body,
            mfa_settings.MFA_FROM_EMAIL or django_settings.DEFAULT_FROM_EMAIL,
            [address],
        )

    def _ensure_code(self, request, user, address, key):
        """Make sure a live code exists for this ceremony, sending one if not.

        Called from begin_enroll/begin_verify, which run on every GET of the
        page -- including a refresh. Reusing a still-valid code rather than
        issuing a new one is what stops an ordinary refresh from spending
        send budget (or, without a throttle, from being an email bomb aimed
        at a third party).

        Past the limit, or when the mail backend itself fails to deliver,
        this returns having done nothing usable: no signal to the caller
        distinguishing "throttled" from "sent" from "delivery failed" --
        see begin_verify's docstring for why the page must look identical
        in every one of those cases.
        """
        state = request.session.get(key)
        if state and _is_fresh(state) and state.get("address") == address:
            return
        if not ratelimit.check(user, SEND_SCOPE, setting=SEND_SETTING):
            return
        code = _issue_code()
        salt = secrets.token_hex(8)
        request.session[key] = {
            "hash": _hash(code, salt),
            "salt": salt,
            "issued_at": time.time(),
            "address": address,
            "attempts": 0,
        }
        # The budget is spent here, before the send is even attempted, and
        # stays spent even if _send() below fails: the costly thing being
        # budgeted is the outbound call to the mail provider, which has
        # already happened by the time _send() can raise. Not moving this
        # after a successful send is what stops a persistent backend outage
        # from turning into an unthrottled loop of real network calls to
        # that provider on every single page load.
        ratelimit.record(user, SEND_SCOPE, setting=SEND_SETTING)
        try:
            self._send(user, address, code)
        except Exception:
            # A mail-backend outage must not surface as an unhandled 500 on
            # the challenge/enroll page -- and, for the same reason a
            # throttled send must not reveal itself (see begin_verify's
            # docstring), it must not be visibly *different* from one
            # either: both end up "no usable code, identical response".
            # Pop the state written above so a later complete_*() correctly
            # reports "invalid" instead of validating a code that was never
            # actually delivered.
            #
            # Not swallowed silently, though: this is the one place in the
            # request that would otherwise know delivery failed, so it logs
            # at ERROR -- a host project with its own error monitoring on
            # `django_mfa` sees every outage even though the user never does.
            logger.exception(
                "django_mfa: failed to send a one-time code to user pk=%s",
                user.pk)
            request.session.pop(key, None)

    def _spend(self, request, key, address, submitted):
        """Check ``submitted`` against the stored ceremony. True or False.

        Pops the state on success, and on the last allowed attempt against
        that code (MAX_ATTEMPTS) -- so one issued code is single-use in
        both directions: it cannot be replayed after it works, and it
        cannot be brute-forced past MAX_ATTEMPTS guesses. See MAX_ATTEMPTS's
        own comment for why that cap bounds one code, not a whole guessing
        session, and for which two settings bound the session itself.
        """
        state = request.session.get(key)
        if not state or not _is_fresh(state) or state.get("address") != address:
            request.session.pop(key, None)
            return False

        if strings_equal(_hash(submitted, state["salt"]), state["hash"]):
            request.session.pop(key, None)
            return True

        attempts = state.get("attempts", 0) + 1
        if attempts >= MAX_ATTEMPTS:
            request.session.pop(key, None)
        else:
            # __setitem__ already flips request.session.modified; no
            # separate assignment needed.
            request.session[key] = {**state, "attempts": attempts}
        return False

    # --- enrollment --------------------------------------------------------

    def begin_enroll(self, request):
        """Send a confirmation code to the account's address.

        Returns address=None rather than raising when there is no address:
        views.enroll.enroll_factor calls this outside its try/except, so an
        exception here is a 500 on a hand-typed URL. is_available() already
        keeps the factor off the security page for such an account.

        Gated on mask_email(address), not the raw address -- see
        is_available()'s docstring for why "deliverable" and "displayable"
        have to be the same check. Includes code_length so the template's
        maxlength/label can track MFA_EMAIL_CODE_LENGTH instead of assuming
        it's 6: a mismatch there means a correctly-emailed code can never be
        typed into the truncated input at all.
        """
        address = user_email(request.user)
        masked = mask_email(address)
        if not masked:
            return {"address": None}
        self._ensure_code(request, request.user, address, ENROLL_STATE_KEY)
        return {"address": masked,
                "code_length": mfa_settings.MFA_EMAIL_CODE_LENGTH}

    def complete_enroll(self, request, data):
        address = user_email(request.user)
        if not address or not self._spend(
                request, ENROLL_STATE_KEY, address, data.get("code", "")):
            raise ValueError("Verification code is expired or invalid.")
        return Authenticator.objects.create(
            user=request.user, type=self.type, data={"address": address})

    # --- verification ------------------------------------------------------

    def _address_for(self, user):
        """The address this user's factor was enrolled against.

        Deliberately the stored one, not user_email(user): a factor is
        possession of a specific mailbox, and silently following a mutable
        profile field means whoever can change that field can redirect the
        factor. Falls back to the profile address only for a row that
        predates the field being stored.
        """
        authenticator = self.get_instances(user).first()
        if authenticator is None:
            return ""
        return authenticator.data.get("address") or user_email(user)

    def begin_verify(self, request, user):
        """Send a challenge code.

        A throttled send renders exactly as a successful one does -- same
        copy, same status, no mail. Telling the user they were throttled
        would hand an attacker a free counter of how many sends remain, and
        the legitimate user's remedy (wait, or pick another method) is the
        same either way. The same now holds for a mail-backend failure --
        see _ensure_code.

        Gated on mask_email(address), matching begin_enroll -- see
        is_available()'s docstring. Includes code_length for the same
        reason begin_enroll does.
        """
        address = self._address_for(user)
        masked = mask_email(address)
        if not masked:
            return {"address": None}
        self._ensure_code(request, user, address, VERIFY_STATE_KEY)
        return {"address": masked,
                "code_length": mfa_settings.MFA_EMAIL_CODE_LENGTH}

    def complete_verify(self, request, user, data):
        address = self._address_for(user)
        if not address or not self._spend(
                request, VERIFY_STATE_KEY, address, data.get("code", "")):
            return False
        authenticator = self.get_instances(user).first()
        if authenticator is None:
            return False
        authenticator.record_usage()
        return True
