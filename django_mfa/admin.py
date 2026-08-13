from django.contrib import admin
from django.contrib.auth import get_user_model

from .models import Authenticator


@admin.register(Authenticator)
class AuthenticatorAdmin(admin.ModelAdmin):
    """Inspect-and-revoke only. Never exposes ``Authenticator.data``.

    That blob holds the TOTP shared secret, the recovery-code hashes and the
    WebAuthn credential. Under the default ModelAdmin it was rendered as an
    editable form field, which made the admin a privilege-escalation surface:
    any staff account with ``view_authenticator`` could read another user's
    TOTP secret -- including a superuser's -- and generate valid codes for
    them, and one with ``change_authenticator`` could overwrite it with a
    secret of its own choosing. ``MFA_SECRET_ENCRYPTION_KEYS`` is not a
    mitigation: django_mfa.crypto *signs*, it does not encrypt, and the
    payload is plain base64 that recovers without any key (see
    docs/security.md).

    ``data`` is therefore absent from ``fields``, ``list_display`` and
    ``get_search_fields()`` alike -- a searchable ``data`` would leak the
    secret a character at a time even while never rendering it -- and adding
    and editing are switched off outright, since nothing in this model is
    meaningfully hand-editable and every write to it is a way to weaken
    somebody's second factor.

    Deleting is deliberately still allowed. Revoking a lost or stolen
    authenticator on behalf of a locked-out user is the one legitimate
    support operation here, and removing it would push operators towards
    editing the database by hand.
    """

    list_display = ("user", "type", "name", "created_at", "last_used_at")
    list_filter = ("type", "created_at", "last_used_at")
    date_hierarchy = "created_at"
    ordering = ("user", "type", "created_at")

    #: Everything except `data`. Also the complete readonly set -- with
    #: has_change_permission() off these render as an inspectable, read-only
    #: detail page rather than a form.
    fields = ("user", "type", "name", "created_at", "last_used_at")
    readonly_fields = fields

    def get_search_fields(self, request):
        # Derived from USERNAME_FIELD rather than hardcoding "username":
        # AUTH_USER_MODEL is swappable and a host project's user model need
        # not have that field at all.
        return ("name", f"user__{get_user_model().USERNAME_FIELD}")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
