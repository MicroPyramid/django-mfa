from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

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
        # Labels are lazily translated: get_type_display() feeds the
        # notification emails (django_mfa/notifications.py) and the admin
        # changelist, so leaving them in English would put an untranslated
        # factor name inside an otherwise translated message.
        #
        # This needs NO migration, which is not obvious: `choices` is part of
        # a field's deconstruction, so changing it normally provokes an
        # AlterField. A gettext_lazy proxy compares equal to the string it
        # wraps, though, so the autodetector sees the same choices it already
        # had. Verified against Django 4.2, 5.2 and 6.1; test_migrations.py's
        # makemigrations --check test is what would catch it regressing.
        TOTP = "totp", _("Authenticator app")
        WEBAUTHN = "webauthn", _("Security key or passkey")
        RECOVERY_CODES = "recovery_codes", _("Recovery codes")
        EMAIL = "email", _("Emailed code")

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
                condition=models.Q(type__in=["totp", "recovery_codes", "email"]),
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


class RateLimitCounter(models.Model):
    """One rate-limit budget's counter, durable across a cache outage.

    The storage half of ``django_mfa.ratelimit`` when
    ``MFA_RATE_LIMIT_BACKEND`` is ``"database"`` (the default). The cache
    backend keeps the identical shape in the cache instead, and the two are
    never both live -- there is one counter for a scope, not a fast copy and
    a slow copy to reconcile.

    Why a table at all: a cache-only counter is erased by a Redis restart, an
    eviction under memory pressure, or ``cache.clear()`` in an unrelated
    deploy step, and every erasure silently hands an attacker mid-run a fresh
    budget. That failure leaves no trace -- the limit simply stops binding --
    which is what makes it worth a write per failed attempt.

    Rows are garbage, not records, once ``expires_at`` passes: nothing reads
    them and ``manage.py mfa_prune`` deletes them. They are not an audit log
    (django_mfa.events is), and ``scope`` holds a client IP for the per-IP
    budget, so treat the table as personal data with a short retention and
    prune it on a schedule -- see docs/operations.md.
    """

    #: "django_mfa:rl:<user pk>:<factor>" for a per-user budget,
    #: "django_mfa:rl:ip:<address>:<factor>" for a per-IP one -- built by
    #: ratelimit._key()/_ip_key(), which own the format, and byte-identical to
    #: the key the cache backend uses so the two can never drift. An IPv6
    #: address contains colons of its own, so this is not parseable back into
    #: fields by splitting; it is an opaque key that happens to stay legible to
    #: an operator reading the table, which is the only reason it is not
    #: hashed.
    scope = models.CharField(max_length=255, unique=True)
    count = models.PositiveIntegerField(default=0)
    #: Indexed because mfa_prune's only query filters on it.
    expires_at = models.DateTimeField(db_index=True)

    def __str__(self):
        return f"{self.scope} ({self.count})"


class MfaExemptionManager(models.Manager):
    def active_for(self, user):
        """This user's exemption if it is currently in force, else None."""
        return self.filter(user=user).filter(
            models.Q(expires_at__isnull=True)
            | models.Q(expires_at__gt=timezone.now())
        ).first()


class MfaExemption(models.Model):
    """A user MFA_REQUIRED does not apply to, despite the predicate.

    Written by the `mfa_disable` management command, never through the web
    UI: exempting somebody from a security requirement is an operator action
    that needs a reason attached and an audit trail (see the
    mfa_exemption_changed signal), not something a user can do to themselves.

    Suppresses MFA_REQUIRED ONLY. It does not open @mfa_required views --
    MFA_REQUIRED picks users, the decorator picks views, and the two are not
    interchangeable (see decorators.py's module docstring).
    """

    user = models.OneToOneField(settings.AUTH_USER_MODEL,
                                related_name="mfa_exemption",
                                on_delete=models.CASCADE)
    reason = models.CharField(max_length=255)
    created_at = models.DateTimeField(default=timezone.now)
    #: None means permanent. A dated exemption is strongly preferred; the
    #: mfa_disable command surfaces --until for exactly that reason.
    expires_at = models.DateTimeField(null=True, blank=True)

    objects = MfaExemptionManager()

    def __str__(self):
        # localtime(), not a bare strftime on the stored value: expires_at is
        # UTC under USE_TZ=True, and formatting it directly shows an operator
        # in a negative-offset timezone a date up to a day earlier than the
        # one the exemption actually expires on. But localtime() itself
        # raises on a naive datetime, and expires_at IS naive under
        # USE_TZ=False (the Django 4.2-era default, still unset by conf.py)
        # -- so only convert when there is a timezone to convert from; a
        # naive value is already in the meaning the operator entered it in.
        expires = self.expires_at
        if expires is not None and timezone.is_aware(expires):
            expires = timezone.localtime(expires)
        suffix = f" until {expires:%Y-%m-%d}" if expires else ""
        return f"MFA exemption for {self.user}{suffix}"

    def is_active(self):
        return self.expires_at is None or self.expires_at > timezone.now()

