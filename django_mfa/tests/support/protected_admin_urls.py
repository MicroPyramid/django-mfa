"""Root URLconf for ProtectedAdminTests / AdminStepUpTests (test_admin.py).

Deliberately a SEPARATE module from support/admin_urls.py, which
AuthenticatorAdminHttpTests and UnprotectedAdminTests use and which never
calls protect_admin_site(). AdminSite.get_urls() wires most admin views
through a wrap() closure that reads self.has_permission fresh on every
request, but `login/` is the one exception -- it is routed straight to
`self.login`, evaluated exactly once, at whatever moment `admin.site.urls`
is first accessed. Because Python caches an imported module in sys.modules
and never re-executes its top-level code, that one evaluation is permanent
for the life of the process.

Fix round 1, Finding 5: the first version of this module relied on test
setUp() to call protect_admin_site() before the first request -- which only
works if ProtectedAdminTests happens to run before any other test imports
this same module, i.e. it was order-dependent (confirmed broken under
`--reverse`). Patching HERE, before `admin.site.urls` is read below,
guarantees the `login/` URL captures the protected view no matter which
test class imports this module first. protect_admin_site() is idempotent,
so a test's own setUp() calling it again is a no-op.
"""

from django.contrib import admin
from django.urls import include, path

from django_mfa.admin_site import protect_admin_site

protect_admin_site(admin.site)

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("django_mfa.urls")),
]
