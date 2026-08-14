import time

SESSION_KEY = "mfa"


def start_pending(request):
    request.session[SESSION_KEY] = {"verified": False, "method": None, "at": None}


def mark_verified(request, method):
    request.session[SESSION_KEY] = {
        "verified": True, "method": method, "at": int(time.time())}


def is_verified(request):
    return bool(request.session.get(SESSION_KEY, {}).get("verified"))


def is_pending(request):
    return SESSION_KEY in request.session and not is_verified(request)


def verified_at(request):
    """Unix timestamp of this session's last successful challenge, or None."""
    return request.session.get(SESSION_KEY, {}).get("at")


def is_fresh(request, max_age):
    """Did this session verify a factor within the last ``max_age`` seconds?

    A verified session with no ``at`` counts as STALE. start_pending() writes
    at=None, and a session verified by 4.1.0 or earlier -- the release before
    anything read this field -- can carry one too. Stale is the safe
    direction: it costs one re-verification and self-heals, where the reverse
    would hand every pre-upgrade session a permanent bypass of the gate.

    Compares against ``int(time.time())``, not the raw float, because ``at``
    is always an integer (mark_verified() stores int(time.time())). Comparing
    a float "now" against an int "at" would make the exactly-at-the-boundary
    case fail almost every time: at is already rounded down by up to ~1s at
    the moment it's stored, so a float "now" taken any time later -- even
    microseconds -- reliably pushes ``now - at`` a hair past ``max_age``.
    """
    if not is_verified(request):
        return False
    at = verified_at(request)
    if at is None:
        return False
    return (int(time.time()) - at) <= max_age


def reset(request):
    request.session.pop(SESSION_KEY, None)
