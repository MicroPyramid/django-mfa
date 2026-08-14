"""Counting failed attempts, and refusing them past a budget.

Three budgets exist, all built out of the same counter:

* ``MFA_VERIFY_RATE_LIMIT`` -- wrong codes per *user*, per factor. Stops one
  account's second factor being guessed.
* ``MFA_VERIFY_IP_RATE_LIMIT`` -- wrong codes per *client IP*, across every
  account. Stops the same guess being sprayed at ten thousand accounts, which
  the per-user budget cannot see at all: each account contributes one failure
  and none of them ever reaches its own limit.
* ``MFA_EMAIL_SEND_RATE_LIMIT`` -- codes *minted*, rather than guessed (see
  adapters/email.py).

Two things about this module are deliberate and easy to "fix" into a
vulnerability:

**A refused attempt must be indistinguishable from a wrong one.** Nothing here
returns *why*; ``check()`` is a bool. views/verify.py renders one generic error
for both, so a lockout is not an oracle telling an attacker when to back off.

**A successful verification clears the user's counter, never the IP's.** See
``clear()``.
"""

import logging
import re
from datetime import timedelta

from django.core.cache import cache
from django.db import DatabaseError, IntegrityError, models, transaction
from django.utils import timezone
from django.utils.module_loading import import_string

from django_mfa.conf import settings as mfa_settings

logger = logging.getLogger(__name__)

UNITS = {"s": 1, "m": 60, "h": 3600}
PATTERN = re.compile(r"^(\d+)/(\d+)([smh])$")

#: Accepted values for MFA_RATE_LIMIT_BACKEND. Validated at startup by
#: checks.check_rate_limit_backend (django_mfa.E008), so a typo is a refused
#: deploy rather than a silently unlimited login page.
BACKENDS = ("database", "cache")


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


def _ip_key(ip, scope):
    """Key for one client address's counter in one scope.

    The ``ip:`` segment is what keeps this from colliding with _key() above:
    a user pk is an integer, so no per-user key can begin ``django_mfa:rl:ip:``.

    Not parseable back into (address, scope) by splitting -- an IPv6 address
    contains colons of its own -- and nothing tries to. It is an opaque key
    that happens to stay legible to an operator reading the RateLimitCounter
    table, which is the only reason the address is not hashed here.
    """
    return f"django_mfa:rl:ip:{ip}:{scope}"


# --- client address ---------------------------------------------------------

def client_ip(request):
    """The address to bill this request's attempt to, or None.

    ``REMOTE_ADDR`` unless ``MFA_CLIENT_IP_RESOLVER`` names something else,
    and that default is the security-relevant part: ``X-Forwarded-For`` is
    **not** read, because a header the client sets breaks the budget in both
    directions at once. An attacker who can vary it spreads their attempts
    across unlimited fictional addresses and is never throttled; an attacker
    who sets it to *your* office's address exhausts that budget and locks your
    staff out. Neither is a corner case -- forging the header is a single
    curl flag.

    Behind a proxy, REMOTE_ADDR is the proxy, so every client shares one
    budget and the limit binds far too early. That is the case
    MFA_CLIENT_IP_RESOLVER exists for: point it at a resolver that knows how
    many hops of XFF your infrastructure appends and which of them it
    guarantees, which is knowledge this package cannot have.

    Returning None disables the per-IP budget for this request rather than
    refusing it -- an address that cannot be determined cannot be billed, and
    failing closed here would deny every request under a misconfiguration
    instead of just under an attack. The per-user budget still applies.
    """
    resolver = mfa_settings.MFA_CLIENT_IP_RESOLVER
    if resolver is None:
        return request.META.get("REMOTE_ADDR") or None
    if isinstance(resolver, str):
        resolver = import_string(resolver)
    return resolver(request) or None


# --- storage ----------------------------------------------------------------
#
# Two backends, one shape: get(key) -> int, incr(key, window), delete(key).
# Exactly one is live at a time (MFA_RATE_LIMIT_BACKEND). They are not a fast
# copy and a durable copy of the same counter -- there is one counter, kept in
# one place, and nothing to reconcile.

def _cache_get(key):
    return cache.get(key, 0)


def _cache_incr(key, window):
    """Count one event against ``key``.

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
        # It expired again in the meantime. Vanishingly unlikely, and an
        # evicted counter is exactly the durability hole the database backend
        # exists to close, so a single lost failure here is consistent.
        cache.set(key, 1, window)


def _cache_delete(key):
    cache.delete(key)


def _db_get(key):
    from django_mfa.models import RateLimitCounter

    count = RateLimitCounter.objects.filter(
        scope=key, expires_at__gt=timezone.now()
    ).values_list("count", flat=True).first()
    return count or 0


def _db_incr(key, window):
    """Count one event against ``key``, atomically.

    Every branch is a single statement whose effect the database serialises,
    for the same reason the cache path uses incr() over get()-then-set(): the
    attack this exists to stop *is* concurrent attempts, so a read-modify-write
    would drop precisely the failures that matter most.
    """
    from django_mfa.models import RateLimitCounter

    now = timezone.now()
    expires_at = now + timedelta(seconds=window)
    rows = RateLimitCounter.objects.filter(scope=key)

    # A live counter: add to it, leaving expires_at alone. The window stays
    # fixed from the first failure rather than sliding forward on each one,
    # matching the cache backend exactly.
    if rows.filter(expires_at__gt=now).update(count=models.F("count") + 1):
        return
    # A counter that has expired: reuse the row with a fresh window. Filtered
    # on expires_at again so this cannot clobber a live counter written by a
    # request that raced in between the two statements.
    if rows.filter(expires_at__lte=now).update(count=1, expires_at=expires_at):
        return
    try:
        # atomic() for the savepoint, not the transaction: under
        # ATOMIC_REQUESTS (or any caller-held atomic block) an IntegrityError
        # marks the whole transaction unusable, so catching one without a
        # savepoint to roll back to breaks every later query in the request.
        with transaction.atomic():
            RateLimitCounter.objects.create(
                scope=key, count=1, expires_at=expires_at)
    except IntegrityError:
        # Another request created it between the UPDATE and the INSERT. Its
        # row is live; count on top of it.
        rows.update(count=models.F("count") + 1)


def _db_delete(key):
    from django_mfa.models import RateLimitCounter

    RateLimitCounter.objects.filter(scope=key).delete()


#: Each backend's (get, incr, delete) and the exception class that means "this
#: store could not answer" -- DatabaseError for the ORM, and bare Exception for
#: the cache, whose clients raise their own unrelated hierarchies
#: (redis.ConnectionError, pylibmc.Error) with no Django base class in common.
_BACKENDS = {
    "database": (_db_get, _db_incr, _db_delete, DatabaseError),
    "cache": (_cache_get, _cache_incr, _cache_delete, Exception),
}


def _backend():
    name = mfa_settings.MFA_RATE_LIMIT_BACKEND
    try:
        return _BACKENDS[name]
    except KeyError:
        raise ValueError(
            f"Invalid MFA_RATE_LIMIT_BACKEND: {name!r} "
            f"(expected one of {', '.join(BACKENDS)})"
        ) from None


def _unavailable(action, key):
    """What to do when the store itself could not answer.

    ``MFA_RATE_LIMIT_FAIL_OPEN`` governs *this* -- an outage, a missing table,
    a refused connection -- and nothing else. It emphatically does not govern
    a counter that is simply absent, which is indistinguishable from "no
    failures yet" and must always be allowed; a limiter that denied on a cache
    miss would deny every first attempt ever made.

    The default is True: availability over a secondary control. An operator
    who would rather refuse verification than let it go unmetered sets it
    False, at the cost of a cache outage becoming a site-wide login outage.
    """
    logger.exception(
        "django_mfa: rate-limit store unavailable during %s of %r", action, key)
    return mfa_settings.MFA_RATE_LIMIT_FAIL_OPEN


# --- the budgets ------------------------------------------------------------

def check(user, scope, setting="MFA_VERIFY_RATE_LIMIT"):
    """Has ``user`` any budget left in ``scope``?"""
    limit, _window = parse(getattr(mfa_settings, setting), setting)
    get, _incr, _delete, unavailable = _backend()
    key = _key(user, scope)
    try:
        return get(key) < limit
    except unavailable:
        return _unavailable("check", key)


def record(user, scope, setting="MFA_VERIFY_RATE_LIMIT"):
    """Count one event against ``user``'s budget for ``scope``."""
    _limit, window = parse(getattr(mfa_settings, setting), setting)
    _get, incr, _delete, unavailable = _backend()
    key = _key(user, scope)
    try:
        incr(key, window)
    except unavailable:
        # Nothing to fail open or closed about: the attempt has already been
        # evaluated, and check() on the next one makes that call with the same
        # setting. Losing the increment is the outage's cost, not a decision.
        logger.exception(
            "django_mfa: rate-limit store unavailable during record of %r", key)


#: The original name, kept because views/verify.py and its tests call it and
#: this refactor must not change the verification path at all. "failure" is
#: accurate for that caller; the generic name is `record`.
record_failure = record


def clear(user, scope):
    """Forget ``user``'s failures in ``scope`` -- called on success only."""
    _get, _incr, delete, unavailable = _backend()
    key = _key(user, scope)
    try:
        delete(key)
    except unavailable:
        logger.exception(
            "django_mfa: rate-limit store unavailable during clear of %r", key)


def check_client(request, scope):
    """Has this request's client address any budget left in ``scope``?

    True when no address can be determined (see client_ip) and when
    ``MFA_VERIFY_IP_RATE_LIMIT`` is None, which switches the budget off for a
    deployment that cannot identify its clients -- behind a CDN it does not
    control, say, where every request would otherwise share one address.
    """
    spec = mfa_settings.MFA_VERIFY_IP_RATE_LIMIT
    if spec is None:
        return True
    ip = client_ip(request)
    if ip is None:
        return True
    limit, _window = parse(spec, "MFA_VERIFY_IP_RATE_LIMIT")
    get, _incr, _delete, unavailable = _backend()
    key = _ip_key(ip, scope)
    try:
        return get(key) < limit
    except unavailable:
        return _unavailable("check", key)


def record_client(request, scope):
    """Count one failure against this request's client address.

    There is no ``clear_client``, and that is the point: a successful
    verification must NOT reset this counter. An attacker spraying an address
    only needs one account of their own -- or one lucky guess in ten thousand
    -- to log into, and clearing on success would hand them a fresh budget
    every time they did. The per-user counter is cleared (a legitimate user
    who fumbles a digit and then succeeds should not carry the failure), the
    shared one is not.
    """
    spec = mfa_settings.MFA_VERIFY_IP_RATE_LIMIT
    if spec is None:
        return
    ip = client_ip(request)
    if ip is None:
        return
    _limit, window = parse(spec, "MFA_VERIFY_IP_RATE_LIMIT")
    _get, incr, _delete, unavailable = _backend()
    key = _ip_key(ip, scope)
    try:
        incr(key, window)
    except unavailable:
        logger.exception(
            "django_mfa: rate-limit store unavailable during record of %r", key)


def prune():
    """Delete expired counters. Returns how many rows went.

    Only meaningful for the database backend -- cache entries expire
    themselves. See the mfa_prune management command.
    """
    from django_mfa.models import RateLimitCounter

    deleted, _by_model = RateLimitCounter.objects.filter(
        expires_at__lte=timezone.now()).delete()
    return deleted
