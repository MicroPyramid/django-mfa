import re

from django.core.cache import cache

from django_mfa.conf import settings as mfa_settings

UNITS = {"s": 1, "m": 60, "h": 3600}
PATTERN = re.compile(r"^(\d+)/(\d+)([smh])$")


def parse(spec):
    match = PATTERN.match(spec)
    if not match:
        raise ValueError(f"Invalid MFA_VERIFY_RATE_LIMIT: {spec!r}")
    count, amount, unit = match.groups()
    count, window = int(count), int(amount) * UNITS[unit]
    # A zero limit locks every user out permanently — check() compares
    # `attempts < limit`, which is false before any failure is recorded. A zero
    # window expires the counter instantly, silently disabling the throttle.
    # Both are almost certainly typos, so refuse them loudly.
    if count < 1:
        raise ValueError(
            f"MFA_VERIFY_RATE_LIMIT count must be at least 1, got {spec!r} — "
            "a zero limit would lock out every user permanently."
        )
    if window < 1:
        raise ValueError(
            f"MFA_VERIFY_RATE_LIMIT window must be at least 1 second, got {spec!r}"
        )
    return count, window


def _key(user, factor_type):
    return f"django_mfa:rl:{user.pk}:{factor_type}"


def check(user, factor_type):
    limit, _window = parse(mfa_settings.MFA_VERIFY_RATE_LIMIT)
    return cache.get(_key(user, factor_type), 0) < limit


def record_failure(user, factor_type):
    _limit, window = parse(mfa_settings.MFA_VERIFY_RATE_LIMIT)
    key = _key(user, factor_type)
    cache.set(key, cache.get(key, 0) + 1, window)


def clear(user, factor_type):
    cache.delete(_key(user, factor_type))
