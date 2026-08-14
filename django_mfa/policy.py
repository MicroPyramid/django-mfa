"""Who is required to hold a second factor.

``MFA_REQUIRED`` answers that question in one of four shapes:

    MFA_REQUIRED = False                      # the default: nobody
    MFA_REQUIRED = True                       # every authenticated user
    MFA_REQUIRED = "myapp.policy.needs_mfa"   # dotted path to predicate(user)
    MFA_REQUIRED = some_callable              # the same, imported yourself

Enrollment is otherwise entirely voluntary: MfaMiddleware only challenges a
user who already holds a factor, so without this setting a user who never
enrolls is never prompted.

This module answers "is this user *required* to have MFA". Whether they
actually have it is registry.primary_enabled_for(user), which stays the
single source of truth for that -- do not add a second definition here.
"""

from functools import cache

from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

from django_mfa.conf import settings as mfa_settings


def is_staff(user):
    """Predicate: require MFA of anyone who can reach the Django admin."""
    return bool(getattr(user, "is_staff", False))


def in_groups(*names):
    """Return a predicate requiring MFA of anyone in one of ``names``.

    A factory, not a predicate -- call it and assign the result:

        MFA_REQUIRED = in_groups("admins", "finance")
    """
    def predicate(user):
        return user.groups.filter(name__in=names).exists()

    predicate.mfa_group_names = tuple(names)
    return predicate


@cache
def _import(path):
    """Import a dotted path once per distinct string.

    Keyed on the path itself rather than cached as a single module-level
    value, so override_settings() in tests (and a host project that changes
    the setting between requests) is honoured rather than pinned to whatever
    was resolved first.
    """
    return import_string(path)


def resolve():
    """Return ``MFA_REQUIRED`` as a callable predicate, or None when off.

    Raises ImproperlyConfigured (or ImportError, from _import) for a value it
    cannot use. Both are caught at startup by checks.check_mfa_required_
    predicate (django_mfa.E004) so the failure surfaces from `manage.py
    check` rather than from inside middleware on a user's first request.
    """
    value = mfa_settings.MFA_REQUIRED
    if value is None or value is False:
        return None
    if value is True:
        return lambda user: True
    if isinstance(value, str):
        value = _import(value)
    if not callable(value):
        raise ImproperlyConfigured(
            f"MFA_REQUIRED must be a bool, a callable, or a dotted path to "
            f"one -- got {value!r}."
        )
    return value


def has_active_exemption(user):
    """Is this user currently exempted from MFA_REQUIRED by an operator?"""
    from django_mfa.models import MfaExemption

    return MfaExemption.objects.active_for(user) is not None


def mfa_required_for(user):
    """Is this user required to hold a primary second factor?"""
    if not getattr(user, "is_authenticated", False):
        return False
    predicate = resolve()
    if not (predicate and predicate(user)):
        return False
    # Checked last, on purpose: an install with the default
    # MFA_REQUIRED = False never reaches the database for this, and one with
    # a predicate pays one query -- MfaExemption.objects.active_for()'s
    # SELECT ... LIMIT 1, not a plain .exists() -- only for the users it
    # matches. It fetches the row rather than a bare bool because a later
    # consumer (the mfa_status command) needs the reason/expiry to display,
    # not just yes/no, and there is no reason for the two to run separate
    # queries for the same answer.
    return not has_active_exemption(user)
