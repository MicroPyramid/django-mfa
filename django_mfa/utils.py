
import unicodedata

try:
    from itertools import izip_longest
except ImportError:
    from itertools import zip_longest as izip_longest

try:
    from urllib.parse import quote
except ImportError:
    from urllib import quote


def build_uri(secret, name, initial_count=None, issuer_name=None):
    """
    Returns the provisioning URI for the OTP; works for either TOTP or HOTP.

    This can then be encoded in a QR Code and used to provision the Google
    Authenticator app.

    For module-internal use.

    See also:
        http://code.google.com/p/google-authenticator/wiki/KeyUriFormat

    @param [String] the hotp/totp secret used to generate the URI
    @param [String] name of the account
    @param [Integer] initial_count starting counter value, defaults to None.
        If none, the OTP type will be assumed as TOTP.
    @param [String] the name of the OTP issuer; this will be the
        organization title of the OTP entry in Authenticator
    @return [String] provisioning uri
    """
    # initial_count may be 0 as a valid param
    is_initial_count_present = (initial_count is not None)

    otp_type = 'hotp' if is_initial_count_present else 'totp'
    base = f'otpauth://{otp_type}/'

    if issuer_name:
        issuer_name = quote(issuer_name)
        base += f'{issuer_name}:'

    uri = f"{base}{quote(name, safe='@')}?secret={secret}"

    if is_initial_count_present:
        uri += f'&counter={initial_count}'

    if issuer_name:
        uri += f'&issuer={issuer_name}'

    return uri


def _compare_digest(s1, s2):
    differences = 0
    for c1, c2 in izip_longest(s1, s2):
        if c1 is None or c2 is None:
            differences = 1
            continue
        differences |= ord(c1) ^ ord(c2)
    return differences == 0


try:
    # Python 3.3+ and 2.7.7+ include a timing-attack-resistant
    # comparison function, which is probably more reliable than ours.
    # Use it if available.
    from hmac import compare_digest

except ImportError:
    compare_digest = _compare_digest


def strings_equal(s1, s2):
    """
    Timing-attack resistant string comparison.

    Normal comparison using == will short-circuit on the first mismatching
    character. This avoids that by scanning the whole string, though we
    still reveal to a timing attack whether the strings are the same
    length.
    """
    # This used to be a try/except around str() whose handler called unicode()
    # -- a Python 2 fallback that, on Python 3, raises NameError instead of
    # doing anything. Since the except was bare, ANY failure in the try block
    # (including KeyboardInterrupt) landed in a handler that could only ever
    # raise NameError, on the timing-safe comparison used for recovery codes.
    # str() is always available here, so there is nothing left to fall back to.
    s1 = unicodedata.normalize('NFKC', str(s1))
    s2 = unicodedata.normalize('NFKC', str(s2))
    return compare_digest(s1, s2)


def user_email(user):
    """The user's email address, via the swappable user model's own field.

    AUTH_USER_MODEL is swappable and a host project's user model need not
    call the field "email" -- get_email_field_name() is the same indirection
    django_mfa.admin already uses for USERNAME_FIELD.
    """
    from django.contrib.auth import get_user_model

    field = get_user_model().get_email_field_name()
    return (getattr(user, field, "") or "").strip()


def mask_email(address):
    """Show enough of an address to recognise, not enough to learn.

    ashwin@example.com -> a****n@example.com

    A local part of one or two characters is masked completely rather than
    partially revealed: "a*@example.com" gives away half of a two-character
    mailbox name. Anything that isn't an address at all returns "", so a
    template can test the value rather than rendering nonsense.

    isinstance-checked before the "@" test, not just falsiness-checked: this
    is reachable from otp_tags.py's template filter on a value that came
    straight out of Authenticator.data, a JSONField a host project could
    write to directly. A truthy non-string there (an int, a list) is not
    caught by `not address`, and "@" not in address raises TypeError on
    anything that isn't a string or a container of strings -- an unhandled
    500 on the security page rather than the "" this function exists to
    return for exactly this kind of garbage input.
    """
    if not isinstance(address, str) or "@" not in address:
        return ""
    local, _, domain = address.partition("@")
    if not local or not domain:
        return ""
    if len(local) <= 2:
        return f"{'*' * len(local)}@{domain}"
    return f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}@{domain}"
