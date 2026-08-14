"""Grace state for a host project's own chrome.

This package renders no site-wide banner itself -- it does not own the
host's base template -- so the one thing it can usefully offer is the state,
site-wide, for the host to render however it likes.

Opt-in: add "django_mfa.context_processors.mfa" to TEMPLATES.
"""

from django.utils.functional import SimpleLazyObject

from django_mfa import policy


def mfa(request):
    """Expose ``mfa_grace`` to every template.

    Lazy for the same reason django.contrib.auth's own context processor is
    lazy about `user`/`perms`: this runs on every template render, and
    policy.grace_state() resolves the MFA_REQUIRED predicate --
    policy.in_groups(...) is a query. A template that never mentions
    mfa_grace must not pay for it.
    """
    user = getattr(request, "user", None)

    def resolve():
        if user is None or not user.is_authenticated:
            return None
        return policy.grace_state(user)

    return {"mfa_grace": SimpleLazyObject(resolve)}
