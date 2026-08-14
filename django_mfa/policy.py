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

import datetime
import math
from dataclasses import dataclass
from functools import cache

from django.conf import settings as django_settings
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone
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
    """Return the effective policy as a callable predicate, or None when off.

    Starts from ``MFA_REQUIRED`` and, when ``MFA_PROTECT_ADMIN`` is on,
    unions in ``is_staff`` -- so a staff user must hold a factor even for an
    install that never sets MFA_REQUIRED at all. MFA_PROTECT_ADMIN does NOT
    write to or override MFA_REQUIRED; the union happens only here, so this
    stays the single function answering "who must hold a factor" and
    mfa_status, mfa_report and both MfaMiddleware rungs stay truthful with no
    changes of their own.

    The union is built FRESH on every call. ``_import()`` is @cache'd on the
    dotted path string (deliberately, so override_settings() is honoured);
    caching the composed predicate alongside it would pin a test that
    toggles MFA_PROTECT_ADMIN to whatever was resolved first.

    Raises ImproperlyConfigured (or ImportError, from _import) for a value it
    cannot use. Both are caught at startup by checks.check_mfa_required_
    predicate (django_mfa.E004) so the failure surfaces from `manage.py
    check` rather than from inside middleware on a user's first request.
    """
    value = mfa_settings.MFA_REQUIRED
    if value is None or value is False:
        predicate = None
    elif value is True:
        def predicate(user):
            return True
    else:
        if isinstance(value, str):
            value = _import(value)
        if not callable(value):
            raise ImproperlyConfigured(
                f"MFA_REQUIRED must be a bool, a callable, or a dotted path "
                f"to one -- got {value!r}."
            )
        predicate = value

    if not mfa_settings.MFA_PROTECT_ADMIN:
        return predicate
    if predicate is None:
        return is_staff

    base = predicate

    def required_or_staff(user):
        return base(user) or is_staff(user)

    return required_or_staff


def has_active_exemption(user):
    """Is this user currently exempted from MFA_REQUIRED by an operator?"""
    from django_mfa.models import MfaExemption

    return MfaExemption.objects.active_for(user) is not None


def _predicate_matches(user):
    """Does MFA_REQUIRED's predicate select this user at all?

    The half mfa_required_for() and _applies() genuinely share. Split out
    rather than duplicated: the two differ only in what they check AFTER
    this, and a security predicate copied into two places is one that will
    be fixed in one place.
    """
    if not getattr(user, "is_authenticated", False):
        return False
    predicate = resolve()
    return bool(predicate and predicate(user))


def mfa_required_for(user):
    """Is this user required to hold a primary second factor?"""
    if not _predicate_matches(user):
        return False
    # Grace before the exemption lookup, on purpose. At this point the
    # predicate is already paid for, MFA_REQUIRED_FROM is a setting and
    # date_joined is already on the loaded user object -- so this clause is
    # free, and an in-grace user short-circuits before
    # has_active_exemption()'s SELECT ... LIMIT 1 and costs LESS than the
    # same user does today.
    #
    # This suppresses MFA_REQUIRED only. It does not open @mfa_required
    # views: decorators.enforcement_state() does not consult policy at all,
    # which is deliberate and is pinned by
    # test_decorators.GraceDoesNotOpenDecoratedViewsTests.
    due = required_at(user)
    if due is not None and timezone.now() < due:
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


@dataclass(frozen=True)
class GraceState:
    """A user who *would* be walled, but is not yet.

    ``days_remaining`` is rounded UP and is for display only -- nothing
    enforces against it. Rounding down would render "0 days left" for a
    window with twenty-three hours still in it, which reads as "expired" to
    the very user it is trying to warn. Enforcement always compares
    timezone.now() against required_at directly.
    """

    required_at: datetime.datetime
    days_remaining: int


def _match_tz(value):
    """Put a datetime into whichever awareness USE_TZ implies.

    Mixed awareness raises TypeError on comparison, and both halves of this
    feature compare user-supplied datetimes (a setting, an anchor) against
    timezone.now(). Follows MfaExemption.__str__'s precedent: convert only
    when there is something to convert, so USE_TZ = False does not raise.
    """
    if value is None:
        return None
    if django_settings.USE_TZ and timezone.is_naive(value):
        return timezone.make_aware(value)
    if not django_settings.USE_TZ and timezone.is_aware(value):
        return timezone.make_naive(value)
    return value


def _as_datetime(value):
    """MFA_REQUIRED_FROM as a comparable datetime. A bare date means midnight."""
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        return _match_tz(value)
    if isinstance(value, datetime.date):
        return _match_tz(datetime.datetime.combine(value, datetime.time.min))
    raise ImproperlyConfigured(
        f"MFA_REQUIRED_FROM must be a date or datetime -- got {value!r}.")


def _period():
    """MFA_GRACE_PERIOD as a timedelta, or None."""
    value = mfa_settings.MFA_GRACE_PERIOD
    if value is None:
        return None
    if isinstance(value, datetime.timedelta):
        return value
    return datetime.timedelta(days=value)


def _anchor(user):
    """Where this user's personal grace window starts, or None for 'no window'.

    getattr rather than user.date_joined: AUTH_USER_MODEL is swappable and a
    host project's user model need not have that field at all. A custom
    resolver returning None means the same thing -- it legitimately has
    nothing to say about some users -- and is documented behaviour, not an
    error. check_grace_configuration (django_mfa.E010) covers only the case
    where an anchor could never resolve for anyone.
    """
    resolver = mfa_settings.MFA_GRACE_ANCHOR
    if resolver is None:
        return _match_tz(getattr(user, "date_joined", None))
    if isinstance(resolver, str):
        resolver = _import(resolver)
    return _match_tz(resolver(user))


def required_at(user):
    """When this user starts being walled, or None for 'already'.

    max(), not min(): a user who joined before MFA_REQUIRED_FROM is governed
    by the cutover, while one who signs up after it still gets their full
    MFA_GRACE_PERIOD. That union is the whole reason no per-user row is
    needed to model this.
    """
    candidates = []

    cutover = _as_datetime(mfa_settings.MFA_REQUIRED_FROM)
    if cutover is not None:
        candidates.append(cutover)

    period = _period()
    if period is not None:
        anchor = _anchor(user)
        if anchor is not None:
            candidates.append(anchor + period)

    return max(candidates) if candidates else None


def _applies(user):
    """Would this user be walled, ignoring grace?

    Used by grace_state() so it can ask "would be walled" without an
    `ignore_grace=` keyword on a security predicate -- a keyword that flips
    a security answer is a footgun however carefully it is documented.
    """
    return _predicate_matches(user) and not has_active_exemption(user)


def grace_state(user):
    """GraceState while this user is in grace, else None.

    Returns a value ONLY when the user would be walled but is not yet:
    the predicate matched, no exemption is in force, and required_at is
    still in the future. None both for users the policy never covers and for
    users already past due -- which is what stops a banner appearing for
    somebody the policy does not apply to, and what lets mfa_report use
    `mfa_required_for(u) or grace_state(u) is not None` as its filter.

    Unlike the grace check inside mfa_required_for(), this pays for the
    predicate and the exemption lookup itself, because it is called
    standalone (context processor, mfa_report, mfa_status) and has to answer
    "would this user be walled" from scratch.
    """
    if not _applies(user):
        return None
    due = required_at(user)
    if due is None:
        return None
    now = timezone.now()
    if now >= due:
        return None
    return GraceState(
        required_at=due,
        days_remaining=math.ceil(
            (due - now) / datetime.timedelta(days=1)))
