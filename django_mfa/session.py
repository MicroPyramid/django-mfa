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


def reset(request):
    request.session.pop(SESSION_KEY, None)
