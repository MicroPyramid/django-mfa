# django_mfa/handles.py
#
# WebAuthn user handles.
#
# The spec's PublicKeyCredentialUserEntity.id ("user handle") is an opaque
# byte string an authenticator stores alongside a discoverable credential and
# hands back during a passwordless (usernameless) login so the relying party
# can look up who is authenticating before any username has been typed.
#
# It must NOT be the username (or anything else human-legible): the handle is
# readable by anyone with access to the authenticator/credential metadata, so
# a legible handle would leak identity, and it would break the moment a user
# renames.
#
# Stored rather than derived. An earlier version of this module signed the
# user's primary key with django.core.signing (keyed off SECRET_KEY). That is
# wrong: rotating SECRET_KEY is a routine, expected security practice, but
# passkeys are registered once and used for years, so a rotation would
# silently make every previously issued handle unresolvable -- breaking
# passwordless login for every user with a passkey, with no way to detect it
# until they try to log in. A stored random value has no dependency on any
# secret and survives key rotation as well as username changes, while still
# leaking no identity (it's an opaque UUID, unrelated to the username or pk).
#
# Lives in its own module, rather than in django_mfa/adapters/webauthn.py or
# a future backends.py, because both WebAuthn registration (this task) and
# passwordless login (a later task) need it, and the latter must not have to
# import the registration adapter module to get it.
import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class MfaUserHandle(models.Model):
    """Stable opaque WebAuthn user handle.

    Stored rather than derived: a handle signed with SECRET_KEY becomes
    unresolvable when that key is rotated, which would break passwordless
    login for every user with a passkey. A stored random value survives key
    rotation and username changes, and leaks no identity.
    """

    user = models.OneToOneField(settings.AUTH_USER_MODEL,
                                related_name="mfa_user_handle",
                                on_delete=models.CASCADE)
    handle = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)


def user_handle_for(user):
    """Return a stable, opaque WebAuthn user handle for ``user``.

    Idempotent: the first call for a given user creates and persists a
    handle; every subsequent call returns the same value.
    """
    obj, _ = MfaUserHandle.objects.get_or_create(user=user)
    return str(obj.handle)


def user_from_handle(handle):
    """Resolve a handle produced by ``user_handle_for`` back to a user.

    Returns ``None`` if the handle is missing, malformed (not a valid UUID),
    or does not match any stored handle -- never raises, since callers use
    this on untrusted client-supplied input during a login ceremony.
    """
    try:
        obj = MfaUserHandle.objects.filter(handle=handle).first()
    except (ValueError, TypeError, ValidationError):
        # UUIDField.get_prep_value() raises django.core.exceptions
        # .ValidationError for a malformed string (confirmed empirically --
        # NOT a bare ValueError/TypeError, despite what that might suggest by
        # analogy with uuid.UUID() itself, which does raise ValueError).
        # filter(handle=None) does not raise at all: it is prepared as a
        # normal `handle IS NULL` lookup, which simply matches zero rows
        # since the column is NOT NULL -- so None flows through to the
        # `return obj.user if obj else None` line below unexceptionally.
        return None
    return obj.user if obj else None
