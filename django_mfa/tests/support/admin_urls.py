# django_mfa/tests/support/admin_urls.py
#
# ROOT_URLCONF for tests that need to drive the real Django admin over HTTP.
# test_runner.py mounts django_mfa.urls at the root (so tests can reverse
# mfa:* names at "/"), which leaves no admin URLs to exercise; this adds them
# without disturbing that default for every other test.
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("django_mfa.urls")),
]
