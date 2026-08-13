import re

from django.core.cache import cache

from django_mfa.conf import settings as mfa_settings

UNITS = {"s": 1, "m": 60, "h": 3600}
PATTERN = re.compile(r"^(\d+)/(\d+)([smh])$")


def parse(spec, setting="MFA_VERIFY_RATE_LIMIT"):
    match = PATTERN.match(spec)
    if not match:
        raise ValueError(f"Invalid {setting}: {spec!r}")
    count, amount, unit = match.groups()
    count, window = int(count), int(amount) * UNITS[unit]
    # A zero limit locks every user out permanently — check() compares
    # `attempts < limit`, which is false before any failure is recorded. A zero
    # window expires the counter instantly, silently disabling the throttle.
    # Both are almost certainly typos, so refuse them loudly.
    if count < 1:
        raise ValueError(
            f"{setting} count must be at least 1, got {spec!r} — "
            "a zero limit would lock out every user permanently."
        )
    if window < 1:
        raise ValueError(
            f"{setting} window must be at least 1 second, got {spec!r}"
        )
    return count, window


def _key(user, scope):
    """Cache key for one user's counter in one rate-limit ``scope``.

    ``scope`` is either a bare factor type (``"totp"``, from
    views/verify.py's per-factor MFA_VERIFY_RATE_LIMIT budget -- always a URL
    segment, e.g. from ``verify_factor(request, factor_type)``, so it can
    never contain a colon) or a colon-namespaced string an adapter defines
    for its own separate budget (e.g. adapters/email.py's SEND_SCOPE =
    "email:send", which throttles *sending* a code rather than guessing one).
    Because a factor-type scope is exactly one of the fixed, colon-free
    values the URL conf can dispatch to, and a namespaced scope always
    contains at least one colon, the two shapes can never collide inside the
    same ``f"...:{scope}"`` key -- there is no factor type and no adapter
    namespace that produce the same string.
    """
    return f"django_mfa:rl:{user.pk}:{scope}"


def check(user, scope, setting="MFA_VERIFY_RATE_LIMIT"):
    limit, _window = parse(getattr(mfa_settings, setting), setting)
    return cache.get(_key(user, scope), 0) < limit


def record(user, scope, setting="MFA_VERIFY_RATE_LIMIT"):
    """Count one event against ``user``'s budget for ``scope``.

    add()-then-incr(), not get()-then-set(). The latter is a read-modify-write
    and loses increments whenever two attempts interleave -- which is not a
    rare edge case here but the exact shape of the attack this function
    exists to stop: an attacker sending guesses in parallel rather than in
    series had most of their failures silently discarded, so a "5 per 5
    minutes" limit stopped binding at their chosen concurrency.

    add() seeds the counter (and its expiry) exactly once, being a no-op when
    the key already exists; incr() is then a single operation, evaluated
    server-side and atomically by every shared cache backend Django ships for
    production use (redis, memcached), and under its own lock in LocMemCache.

    Note this makes the window fixed from the first failure rather than
    sliding forward on each one, since only add() carries a timeout. That is
    the ordinary reading of "5/5m" and is the stricter-to-reason-about of the
    two; the previous behaviour extended the lockout on every attempt.
    """
    _limit, window = parse(getattr(mfa_settings, setting), setting)
    key = _key(user, scope)
    try:
        cache.incr(key)
        return
    except ValueError:
        pass  # No counter yet (or it just expired) -- seed one below.

    # add(), never set(), for the seed: add() is a no-op when the key already
    # exists, so a request that raced another one to seed the counter cannot
    # reset it to a lower value. Seeding straight to 1 (rather than 0 and then
    # incrementing) keeps this to a single write, so there is no window in
    # which the counter sits at 0 and a concurrent increment can be lost.
    if cache.add(key, 1, window):
        return
    try:
        # Lost the race to seed: the winner's counter is live, count on top.
        cache.incr(key)
    except ValueError:
        # It expired again in the meantime. Vanishingly unlikely, and the
        # throttle already fails open on an evicted counter by design (see
        # check()), so a single lost failure here is consistent with that.
        cache.set(key, 1, window)


#: The original name, kept because views/verify.py and its tests call it and
#: this refactor must not change the verification path at all. "failure" is
#: accurate for that caller; the generic name is `record`.
record_failure = record


def clear(user, scope):
    cache.delete(_key(user, scope))
