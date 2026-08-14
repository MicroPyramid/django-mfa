"""Second-factor protection for the Django admin.

The admin is the single most common reason a project wants MFA at all, and
the settings-only recipe (MFA_REQUIRED = is_staff, plus MfaMiddleware, plus
no admin path in MFA_EXEMPT_PATHS) fails SILENTLY if any part is missed.
This enforces it from inside the admin site, so it holds with no middleware
installed.

Neither override restates a rule. has_permission() reads
decorators.enforcement_state(); login() renders it through
decorators.enforcement_redirect(), which is public for exactly this reason.
"""

import functools

from django.contrib.auth.views import redirect_to_login
from django.shortcuts import resolve_url
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache

from django_mfa import decorators
from django_mfa.conf import settings as mfa_settings

#: Marks a site instance as already wrapped. Some runners call AppConfig.
#: ready() more than once, and double-wrapping would evaluate every gate
#: twice per request.
_PATCHED = "_django_mfa_protected"


def _gates_pass(request):
    """Does this request clear every MFA gate the admin imposes?

    Deliberately does not re-check MFA_PROTECT_ADMIN here -- once
    protect_admin_site() has patched a site, the gate stays active for that
    site's lifetime regardless of what the setting says afterward. Right for
    production (nothing ever flips this off mid-process), but worth knowing
    if a test suite patches a site directly and expects toggling the setting
    alone to unpatch it -- it doesn't; call protect_admin_site() again after
    removing the patch attributes, or don't patch until the setting is what
    you want.
    """
    if decorators.enforcement_state(request) is not None:
        return False
    if (mfa_settings.MFA_ADMIN_STEPUP
            and decorators.recent_enforcement_state(request) is not None):
        return False
    return True


def _login_redirect(request):
    """Where an authenticated-but-ungated admin request goes, or None.

    Only ever acts on an authenticated user. AdminSite.admin_view renders a
    failed has_permission() as a redirect to admin:login, so without this an
    already-logged-in staff user is shown a login form -- confusing, and
    django-two-factor-auth's long-standing wart. An anonymous user is left
    entirely alone: the admin's own form is the right answer for them, and
    enforcement_redirect()'s UNAUTHENTICATED branch must not compete with it.

    next_url is the admin index rather than request.get_full_path(), which
    here is /admin/login/?next=... -- replaying that after verifying is a
    round trip through a login view the user is already past.
    """
    if not request.user.is_authenticated:
        return None

    next_url = request.GET.get("next") or reverse("admin:index")

    response = decorators.enforcement_redirect(request, next_url=next_url)
    if response is not None:
        return response

    # enforcement_state() passed but the step-up rung has not: MFA_ADMIN_STEPUP
    # is on and the challenge is older than MFA_STEPUP_MAX_AGE. Admin pages
    # reaching this are GETs, so replaying the path is safe and
    # _enforce_recent()'s POST carve-out does not apply.
    if (mfa_settings.MFA_ADMIN_STEPUP
            and decorators.recent_enforcement_state(request) is not None):
        return redirect_to_login(
            next_url, resolve_url(reverse("mfa:verify")), "next")

    return None


class MfaAdminMixin:
    """Mix in front of AdminSite to require a verified session.

    Public for hosts that would rather wire this explicitly than let
    MFA_PROTECT_ADMIN patch the default site. That route needs an AdminConfig
    subclass with default_site in INSTALLED_APPS, which is not a one-liner
    and collides with any other package claiming default_site -- hence the
    setting being the advertised path.
    """

    def has_permission(self, request):
        return super().has_permission(request) and _gates_pass(request)

    @method_decorator(never_cache)
    def login(self, request, extra_context=None):
        response = _login_redirect(request)
        if response is not None:
            return response
        return super().login(request, extra_context)

    # AdminSite.login is decorated `@login_not_required` (Django >= 5.1),
    # which LoginRequiredMiddleware reads off the URL pattern's callable to
    # decide whether an anonymous request may reach it at all. Overriding
    # the method here replaces that callable and drops the marker unless it
    # is restored explicitly -- without this, an anonymous visitor to
    # admin:login is bounced to LOGIN_URL by that middleware, which is
    # usually a page that doesn't exist. Setting the attribute directly
    # (rather than importing login_not_required) keeps this working on
    # Django 4.2, which has neither the decorator nor anything that reads
    # the attribute -- the assignment is simply inert there.
    login.login_required = False


def protect_admin_site(site):
    """Wrap an existing AdminSite instance in place.

    Wraps the bound methods rather than swapping the class, so this composes
    with a host project's own AdminSite subclass instead of replacing it --
    and so there is no zero-argument super() to break when a function is
    bound to an instance after class creation.

    Timing is two different stories for the two methods this patches, and
    only one of them is forgiving:

    - has_permission is read fresh on every request -- AdminSite.get_urls()
      wraps most views in a closure that calls ``self.has_permission(request)``
      at call time, not at get_urls() time -- so patching it is safe
      regardless of when get_urls() first runs relative to this call.
    - login is NOT read fresh. AdminSite.get_urls() wires the `login/` URL
      directly to ``self.login`` (unlike every other view, it is not passed
      through that closure), so whatever ``self.login`` resolves to AT THE
      MOMENT get_urls() first runs is what every future request to
      admin:login gets, forever -- get_urls() only ever runs once, the
      first time admin.site.urls is accessed, and Python caches the
      importing module so nothing re-evaluates it later. This function
      MUST therefore run before the URLconf module that mounts admin.site.urls
      is first imported. Calling it from AppConfig.ready() satisfies that in
      a normal deployment, since URL resolution is lazy and does not happen
      until the first real request, well after django.setup() (and every
      app's ready()) has completed.
    """
    if getattr(site, _PATCHED, False):
        return

    original_has_permission = site.has_permission
    original_login = site.login

    def has_permission(request):
        return original_has_permission(request) and _gates_pass(request)

    @never_cache
    def login(request, extra_context=None):
        response = _login_redirect(request)
        if response is not None:
            return response
        return original_login(request, extra_context)

    # original_login is AdminSite.login, decorated `@login_not_required`
    # (Django >= 5.1) so LoginRequiredMiddleware lets an anonymous visitor
    # reach it at all -- that decorator just sets login_required = False in
    # the function's __dict__. update_wrapper copies __dict__, so this
    # carries the marker (and anything else a host's own AdminSite subclass
    # set) onto the replacement without this module needing to import
    # login_not_required itself, which does not exist before Django 5.1 and
    # would break the Django 4.2 floor. Applied after @never_cache so the
    # final object -- what site.login actually becomes -- is the one that
    # gets the copy, not an intermediate.
    functools.update_wrapper(login, original_login)

    site.has_permission = has_permission
    site.login = login
    setattr(site, _PATCHED, True)
