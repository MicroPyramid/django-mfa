
import datetime
import time

from django_mfa import utils
from django_mfa.otp import OTP


class TOTP(OTP):
    def __init__(self, *args, **kwargs):
        """
        @option options [Integer] interval (30) the time interval in seconds
            for OTP This defaults to 30 which is standard.
        """
        self.interval = kwargs.pop('interval', 30)
        super().__init__(*args, **kwargs)

    def at(self, for_time, counter_offset=0):
        """
        Accepts either a Unix timestamp integer or a Time object.
        Time objects will be adjusted to UTC automatically
        @param [Time/Integer] time the time to generate an OTP for
        @param [Integer] counter_offset an amount of ticks to add to the time counter
        """
        if not isinstance(for_time, datetime.datetime):
            for_time = datetime.datetime.fromtimestamp(int(for_time))
        return self.generate_otp(self.timecode(for_time) + counter_offset)

    def now(self):
        """
        Generate the current time OTP
        @return [Integer] the OTP as an integer
        """
        return self.generate_otp(self.timecode(datetime.datetime.now()))

    def match(self, otp, for_time=None, valid_window=0):
        """Return the time counter ``otp`` is valid for, or None.

        ``verify()`` answers "is this code currently valid"; this answers
        "*which* time step was it valid for". A caller needs that to enforce
        single-use (RFC 6238 section 5.2, "the verifier MUST NOT accept the
        second attempt of the OTP generated within the same time window"),
        which a bare boolean cannot express across a non-zero valid_window:
        knowing only that some code in the +/-1 range matched is not enough
        to tell a fresh code from a replay of an earlier one.
        """
        if for_time is None:
            for_time = datetime.datetime.now()
        if not isinstance(for_time, datetime.datetime):
            for_time = datetime.datetime.fromtimestamp(int(for_time))

        counter = self.timecode(for_time)
        for i in range(-valid_window, valid_window + 1):
            if utils.strings_equal(str(otp), str(self.generate_otp(counter + i))):
                return counter + i
        return None

    def verify(self, otp, for_time=None, valid_window=0):
        """
        Verifies the OTP passed in against the current time OTP
        @param [String/Integer] otp the OTP to check against
        @param [Integer] valid_window extends the validity to this many
            counter ticks before and after the current one
        """
        return self.match(otp, for_time, valid_window) is not None

    def provisioning_uri(self, name, issuer_name=None):
        """
        Returns the provisioning URI for the OTP
        This can then be encoded in a QR Code and used
        to provision the Google Authenticator app
        @param [String] name of the account
        @return [String] provisioning uri
        """
        return utils.build_uri(self.secret, name, issuer_name=issuer_name)

    def timecode(self, for_time):
        i = time.mktime(for_time.timetuple())
        return int(i / self.interval)
