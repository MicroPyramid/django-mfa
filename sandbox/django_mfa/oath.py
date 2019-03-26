from __future__ import division

import datetime
import struct
import hmac
import hashlib
import time
import six


def hotp(key, counter, digits=6):
    """
    These test vectors come from RFC-4226
    (https://tools.ietf.org/html/rfc4226#page-32).

    >>> key = b'12345678901234567890'
    >>> for c in range(10):
    ...     hotp(key, c)
    '755224'
    '287082'
    '359152'
    '969429'
    '338314'
    '254676'
    '287922'
    '162583'
    '399871'
    '520489'
    """

    msg = struct.pack('>Q', counter)
    hs = hmac.new(key, msg, hashlib.sha1).digest()
    offset = six.indexbytes(hs, 19) & 0x0f
    val = struct.unpack('>L', hs[offset:offset + 4])[0] & 0x7fffffff
    return '{val:0{digits}d}'.format(val=val % 10 ** digits, digits=digits)


def T(t, step=30):
    """
    The TOTP T value (number of time steps since the epoch)
    """
    if hasattr(t, 'timestamp'):
        timestamp = t.timestamp()
    else:
        # python 2
        if t.tzinfo is None:
            timestamp = time.mktime(t.timetuple())
        else:
            utc_naive = t.replace(tzinfo=None) - t.utcoffset()
            timestamp = (utc_naive - datetime.datetime(1970, 1, 1)
                         ).total_seconds()

    return int(timestamp) // step


def totp(key, t, digits=6, step=30):
    """
    These test vectors come from RFC-6238
    (https://tools.ietf.org/html/rfc6238#appendix-B).
    >>> import datetime
    >>> key = b'12345678901234567890'
    >>> totp(key, datetime.datetime.fromtimestamp(59), digits=8)
    '94287082'
    >>> totp(key, datetime.datetime.fromtimestamp(1111111109), digits=8)
    '07081804'
    >>> totp(key, datetime.datetime.fromtimestamp(20000000000), digits=8)
    '65353130'
    """
    return hotp(key, T(t, step), digits)
