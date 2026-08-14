"""Root URLconf for the JSON API tests.

The suite's default ROOT_URLCONF is `django_mfa.urls` (see test_runner.py),
which mounts the HTML views at `/` and does not mount the API at all --
the API being opt-in is the point, and most tests should exercise the
default. This adds it under a prefix, the way a host project would.

A prefix, not `/`, on purpose: it is what makes the tests notice if
anything in the API or the middleware ever assumes the API lives at the
root.
"""

from django.urls import include, path

urlpatterns = [
    path("", include("django_mfa.urls")),
    path("api/mfa/", include("django_mfa.api.urls")),
]
