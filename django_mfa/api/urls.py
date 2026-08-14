"""URLs for the JSON API.

Mounted by the host project, wherever it likes::

    path("api/mfa/", include("django_mfa.api.urls"))

The ``mfa_api`` namespace is baked into the pattern list, the same way
``django_mfa/urls.py`` bakes in ``mfa`` -- do not pass ``namespace=`` to
include(). MfaMiddleware reverses these names to build its exempt sets, so
the namespace has to be predictable rather than whatever a host chose.
"""

from django.urls import include, path

from django_mfa.api import views

api_patterns = ([
    path("state/", views.state, name="state"),
    path("session/", views.mfa_session, name="session"),

    path("enroll/<str:factor_type>/begin/",
         views.enroll_begin, name="enroll_begin"),
    path("enroll/<str:factor_type>/complete/",
         views.enroll_complete, name="enroll_complete"),

    path("verify/<str:factor_type>/begin/",
         views.verify_begin, name="verify_begin"),
    path("verify/<str:factor_type>/complete/",
         views.verify_complete, name="verify_complete"),

    path("recovery-codes/", views.recovery_codes, name="recovery_codes"),
    path("factors/<str:pk>/", views.remove_factor, name="remove_factor"),

    path("passkey/begin/", views.passkey_begin, name="passkey_begin"),
    path("passkey/complete/", views.passkey_complete, name="passkey_complete"),
], "mfa_api")

urlpatterns = [path("", include(api_patterns))]


#: The namespace MfaMiddleware recognises a request to this API by. See
#: MfaMiddleware.is_api_request.
NAMESPACE = "mfa_api"
