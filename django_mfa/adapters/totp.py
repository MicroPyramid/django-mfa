import base64
import codecs
import random
import re

from django_mfa import totp as totp_mod
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


def generate_secret():
    raw = codecs.decode(codecs.encode(f"{random.getrandbits(80):020x}"),
                        "hex_codec")
    return base64.b32encode(raw).decode("utf-8")


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
        if totp_mod.TOTP(decrypt(auth.data["secret"])).verify(
                data.get("code", ""), valid_window=TOTP_VALID_WINDOW):
            auth.record_usage()
            return True
        return False
