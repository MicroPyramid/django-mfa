import base64
import re
import secrets

from django_mfa import totp as totp_mod
from django_mfa.atomic import update_data
from django_mfa.conf import settings as mfa_settings
from django_mfa.crypto import decrypt, encrypt
from django_mfa.models import Authenticator
from django_mfa.registry import Adapter

#: Accept the previous and next 30-second code as well as the current one.
#: The legacy code used 0 (no tolerance), which rejects a correct code when the
#: phone's clock drifts a few seconds or the user submits across a window
#: boundary. 1 is what Google Authenticator, django-otp and allauth all use.
#: The 3x larger guess space is immaterial against a 6-digit code, and a later
#: task adds rate limiting on top.
TOTP_VALID_WINDOW = 1


#: RFC 4226 R6: "The algorithm MUST use a strong shared secret. The length of
#: the shared secret MUST be at least 128 bits. This document RECOMMENDs a
#: shared secret length of 160 bits." 20 bytes also base32-encodes to exactly
#: 32 characters with no '=' padding, which matters: OTP.byte_secret() re-pads
#: self.secret in place and provisioning_uri() embeds the secret verbatim in
#: the otpauth:// query string, so a padded secret would put '=' mid-URI.
SECRET_BYTES = 20


def generate_secret():
    """Return a fresh base32 TOTP shared secret.

    Uses `secrets` (os.urandom) rather than the `random` module. This
    previously drew from random.getrandbits(80): the Mersenne Twister is not
    a CSPRNG -- its 19937-bit state is recoverable from 624 observed 32-bit
    outputs, after which every subsequently issued secret is predictable --
    and it is the process-global instance shared with all other application
    code. 80 bits was also below the RFC 4226 floor.
    """
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("utf-8")


class TOTPAdapter(Adapter):
    type = Authenticator.Type.TOTP
    verbose_name = "Authenticator app"

    def begin_enroll(self, request):
        secret = generate_secret()
        uri = totp_mod.TOTP(secret).provisioning_uri(
            request.user.get_username(),
            issuer_name=mfa_settings.MFA_ISSUER_NAME,
        )
        return {"secret_key": secret, "provisioning_uri": re.sub(r"=+$", "", uri)}

    def complete_enroll(self, request, data):
        secret = data["secret_key"]
        if not totp_mod.TOTP(secret).verify(
                data["code"], valid_window=TOTP_VALID_WINDOW):
            raise ValueError("Verification code did not match.")
        return Authenticator.objects.create(
            user=request.user, type=self.type, data={"secret": encrypt(secret)})

    def begin_verify(self, request, user):
        return {}

    def complete_verify(self, request, user, data):
        auth = self.get_instances(user).first()
        if auth is None:
            return False
        counter = totp_mod.TOTP(decrypt(auth.data["secret"])).match(
            data.get("code", ""), valid_window=TOTP_VALID_WINDOW)
        if counter is None:
            return False
        # RFC 6238 section 5.2: an OTP must not be accepted twice. Rejecting
        # any counter at or below the last accepted one closes both the
        # straight replay of the same code and the replay of an *earlier*
        # still-in-window code after a later one has been used -- with
        # TOTP_VALID_WINDOW = 1 a code would otherwise stay replayable for
        # about 90 seconds, which is ample for a shoulder-surfed or
        # phished-then-forwarded code.
        #
        # The compare-and-set is what makes this hold under concurrency: two
        # simultaneous POSTs of the same code both match here, and without it
        # both would go on to succeed.
        def spend(data):
            if counter <= data.get("last_verified_counter", -1):
                return None
            return {**data, "last_verified_counter": counter}

        if not update_data(auth, spend):
            return False
        auth.record_usage()
        return True
