"""Who is making this API request.

By default: whoever ``request.user`` says, i.e. Django's session
authentication, which is what a same-origin SPA already has.

``MFA_API_AUTHENTICATION`` replaces that with a dotted path to
``callable(request) -> user | None`` for a project whose API clients
authenticate some other way -- a DRF token, a JWT, an API key. It answers
*identity only*; every other decision (pending, enrolled, fresh) is made
from the same state the browser flow uses.

That last point is a real constraint rather than a footnote: MFA state lives
in the *session*, so a client must carry the session cookie for a completed
challenge to still count on the next request. A pure token client that
discards cookies can call these endpoints, but every request looks like a
brand new session to it, and a verification will never stick. See
docs/rest_api.md.
"""

from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

from django_mfa.conf import settings as mfa_settings


def resolve():
    """``MFA_API_AUTHENTICATION`` as a callable, or None when unset.

    Raises ImproperlyConfigured for a value it cannot use. Caught at startup
    by checks.check_mfa_api_authentication (django_mfa.E006), so a typo
    surfaces from `manage.py check` rather than as a 500 on a client's first
    request -- the same treatment MFA_REQUIRED gets.
    """
    value = mfa_settings.MFA_API_AUTHENTICATION
    if value is None:
        return None
    if isinstance(value, str):
        value = import_string(value)
    if not callable(value):
        raise ImproperlyConfigured(
            f"MFA_API_AUTHENTICATION must be a callable, or a dotted path to "
            f"one -- got {value!r}.")
    return value


def resolve_user(request):
    """The authenticated user for this request, or None.

    Callers assign the result to ``request.user`` before doing anything
    else. That is not tidiness: the adapters create and query
    ``Authenticator`` rows against ``request.user`` directly, so a resolver
    that returned a different user without this would enroll a factor onto
    the wrong account.
    """
    resolver = resolve()
    user = resolver(request) if resolver else getattr(request, "user", None)
    if user is None or not getattr(user, "is_authenticated", False):
        return None
    return user
