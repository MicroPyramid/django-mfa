"""Shared helpers for django_mfa's management commands."""

from django.contrib.auth import get_user_model
from django.core.management import CommandError
from django.utils import timezone


def resolve_user(identifier):
    """Find a user by USERNAME_FIELD, falling back to pk.

    USERNAME_FIELD first, then pk only when the first lookup missed and the
    identifier is all digits -- so an installation whose usernames are
    numeric still resolves the username, which is the value an operator
    typed on purpose.

    Derived from USERNAME_FIELD rather than hardcoding "username":
    AUTH_USER_MODEL is swappable and a host project's user model need not
    have that field at all (AuthenticatorAdmin.get_search_fields does the
    same).
    """
    model = get_user_model()
    field = model.USERNAME_FIELD
    user = model.objects.filter(**{field: identifier}).first()
    if user is not None:
        return user
    if identifier.isdigit():
        user = model.objects.filter(pk=int(identifier)).first()
        if user is not None:
            return user
    raise CommandError(
        f"No user matched {identifier!r} — tried {field} (username) and pk."
    )


def format_date(value):
    """Format a datetime as YYYY-MM-DD in the operator's local timezone.

    Guarded on is_aware(): timezone.localtime() raises ValueError on a
    naive datetime, and USE_TZ is False by default on Django 4.2, this
    package's floor. Same guard as MfaExemption.__str__ (django_mfa/models.py)
    -- duplicated here rather than shared because unifying the two copies is
    a later-pass refactor, out of scope for the command that first needed it.
    """
    if timezone.is_aware(value):
        value = timezone.localtime(value)
    return f"{value:%Y-%m-%d}"


def describe_authenticator(auth):
    """One human-readable line for an Authenticator.

    NEVER includes `auth.data`: it holds the TOTP shared secret, the
    recovery-code hashes and the WebAuthn credential. See AuthenticatorAdmin's
    docstring for why that blob stays unprinted everywhere, not just in the
    admin.
    """
    parts = [auth.get_type_display()]
    if auth.name:
        parts.append(f"({auth.name})")
    parts.append(f"added {format_date(auth.created_at)}")
    parts.append(f"last used {format_date(auth.last_used_at)}"
                 if auth.last_used_at else "never used")
    return " ".join(parts)
