from django.conf import settings
from django.db import models
from django.utils import timezone

# Whether a factor type counts as "primary" (protects a user on its own) is
# NOT decided here. It used to be a second, independent definition
# (a frozenset of type strings) that could -- and did -- silently diverge
# from django_mfa.registry.Adapter.counts_as_primary_factor, the one place
# that actually matters (see django_mfa.signals.stamp_pending_verification
# and django_mfa.views.verify.verify_factor, the production callers of that
# decision). The registry is the single source of truth: use
# registry.primary_enabled_for(user) instead.


class AuthenticatorManager(models.Manager):
    def for_user(self, user):
        return self.filter(user=user)


class Authenticator(models.Model):
    class Type(models.TextChoices):
        TOTP = "totp", "Authenticator app"
        WEBAUTHN = "webauthn", "Security key or passkey"
        RECOVERY_CODES = "recovery_codes", "Recovery codes"

    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             related_name="mfa_authenticators",
                             on_delete=models.CASCADE)
    type = models.CharField(max_length=32, choices=Type.choices)
    name = models.CharField(max_length=100, blank=True)
    data = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)
    last_used_at = models.DateTimeField(null=True, blank=True)

    objects = AuthenticatorManager()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user", "type"],
                condition=models.Q(type__in=["totp", "recovery_codes"]),
                name="mfa_one_singleton_authenticator_per_user",
            ),
        ]

    def __str__(self):
        # `name` is WebAuthn-only and optional; without it several security
        # keys belonging to one user are indistinguishable in the admin.
        label = self.get_type_display()
        return f"{label} ({self.name})" if self.name else label

    def record_usage(self):
        self.last_used_at = timezone.now()
        self.save(update_fields=["last_used_at"])

