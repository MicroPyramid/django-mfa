"""A URLconf whose only admin is a project-built site using MfaAdminMixin.

Kept in a module of its own, imported by nothing but the resolver, so a test
can prove check_admin_stepup() loads the URLconf before looking for one.
"""

from django.contrib.admin import AdminSite
from django.urls import path

from django_mfa.admin_site import MfaAdminMixin


class StaffSite(MfaAdminMixin, AdminSite):
    pass


site = StaffSite(name="staff_admin")

urlpatterns = [path("staff/", site.urls)]
