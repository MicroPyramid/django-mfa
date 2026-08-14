"""A JSON interface to the same factors the HTML views drive.

Opt-in. Mount it where you like, alongside (or instead of) the HTML views::

    urlpatterns += [path("api/mfa/", include("django_mfa.api.urls"))]

Nothing here is registered by installing the app, deliberately: an upgrade
must not silently give an existing deployment a new, unauthenticated-by-
default-looking surface it never asked for. This matches how the email
factor, MFA_REQUIRED and change notifications all default to off.

The views are thin on purpose. Every security decision they make is imported
rather than written here:

* the order of operations for an attempt -- ``django_mfa.flows``
* who may make it -- ``django_mfa.decorators.enforcement_state`` and
  ``recent_enforcement_state``, the same predicates the decorators render as
  redirects
* what a factor actually does -- the adapters, unchanged

so that a JSON client cannot end up held to a weaker standard than a browser.
That is a failure nobody notices from the outside: both layers keep working,
and only one of them is enforcing.
"""
