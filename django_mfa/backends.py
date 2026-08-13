# django_mfa/backends.py
#
# Authentication backend for passwordless (passkey) login.
#
# The actual WebAuthn assertion is validated entirely by
# django_mfa.views.verify.passkey_complete BEFORE this backend is ever
# consulted -- authenticate() here does no cryptographic work of its own. Its
# only job is to hand back the user the view already resolved and verified,
# through the standard django.contrib.auth.login()/get_user() contract, so
# that a passkey-authenticated session behaves like any other authenticated
# session (request.user, session persistence across requests, etc.).
#
# user_handle_for()/user_from_handle() are NOT redefined here: they were
# built in django_mfa/handles.py (a stored, random MfaUserHandle row, not the
# django.core.signing-based scheme an earlier version of the spec assumed --
# see handles.py's module docstring for why that changed). Re-exported here
# under `# noqa: F401` because django_mfa.tests.test_passwordless imports
# them from this module, per the task brief's interface contract.
from django.contrib.auth import get_user_model

from django_mfa.handles import user_from_handle, user_handle_for  # noqa: F401


class WebAuthnBackend:
    """Authenticates a user from a verified WebAuthn assertion.

    The assertion is validated by the view before this is called; the
    backend's job is only to resolve and return the user. ``authenticate()``
    deliberately does not accept the standard ``username``/``password``
    keywords other backends look for -- passing this backend a username and
    password (e.g. because some other code in the AUTHENTICATION_BACKENDS
    chain tries every backend with the same call) must not accidentally
    authenticate anyone; it only ever returns a user when the caller
    explicitly hands it one via ``mfa_user`` (the passkey view, having
    already verified the assertion, is the only such caller).
    """

    def authenticate(self, request, mfa_user=None, **kwargs):
        return mfa_user

    def get_user(self, user_id):
        return get_user_model().objects.filter(pk=user_id).first()
