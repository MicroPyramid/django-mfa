# django_mfa/registry.py
from django_mfa.models import Authenticator


class Adapter:
    """Base class for a single MFA factor.

    Subclasses set ``type`` to an ``Authenticator.Type`` value and implement the
    enroll/verify pairs. ``begin_*`` returns a dict of template context and
    stashes any challenge in the session; ``complete_*`` consumes the POSTed
    payload.
    """

    type = None
    verbose_name = None
    supports_multiple = False

    #: Whether this factor is added through the enroll flow at all.
    #: False for recovery codes: they are *generated* (at mfa:recovery_codes),
    #: not enrolled, and implement no begin_enroll/complete_enroll. A factor
    #: with this False is never offered by available_for() and is rejected
    #: with a 404 by views.enroll.enroll_factor -- without that, the security
    #: page renders an "add recovery codes" link whose target raises
    #: NotImplementedError from Adapter.begin_enroll (a 500 on a link this
    #: package itself puts in front of every user who has no codes yet).
    supports_enroll = True

    #: Whether holding only this factor means the user is protected. False for
    #: recovery codes: they are exhaustible and must never be a user's sole
    #: second factor. This is the SINGLE source of truth for that question --
    #: see Registry.primary_enabled_for() below and its two production
    #: callers, django_mfa.signals.stamp_pending_verification and
    #: django_mfa.views.verify.verify_factor.
    counts_as_primary_factor = True

    def is_available(self, user):
        """May this user add (another) instance of this factor?

        This is an enrollment-capacity check only: singleton factors (like
        TOTP) become unavailable once the user already has one, while
        ``supports_multiple`` factors (like WebAuthn) are always available.

        It does NOT encode site-level policy about which factor types are
        permitted at all (e.g. a future ``MFA_UNALLOWED_METHODS`` setting).
        That kind of gating must be composed as a separate filter on top of
        this — do not fold it into this method or into ``Adapter`` subclasses.
        """
        if self.supports_multiple:
            return True
        return not self.get_instances(user).exists()

    def get_instances(self, user):
        return Authenticator.objects.filter(user=user, type=self.type)

    def is_enabled(self, user):
        return self.get_instances(user).exists()

    def begin_enroll(self, request):
        raise NotImplementedError

    def complete_enroll(self, request, data):
        """Validate ``data`` and create the Authenticator row.

        MUST return the created ``Authenticator``: ``views.enroll`` passes it
        straight to the ``factor_added`` signal, so a factor that returns
        ``None`` here silently degrades every host project's audit log and
        notification for that factor type. Raise ``ValueError`` to reject the
        submission -- the view turns that into the same generic 400 a wrong
        code gets.
        """
        raise NotImplementedError

    def begin_verify(self, request, user):
        raise NotImplementedError

    def complete_verify(self, request, user, data):
        raise NotImplementedError

    @property
    def enroll_template(self):
        return f"django_mfa/enroll_{self.type}.html"

    @property
    def verify_template(self):
        return f"django_mfa/verify_{self.type}.html"


class Registry:
    def __init__(self):
        self._adapters = {}

    def register(self, adapter):
        if adapter.type in self._adapters:
            raise ValueError(f"Adapter for {adapter.type!r} already registered")
        self._adapters[adapter.type] = adapter

    def unregister(self, type):
        """Remove the adapter registered for ``type``.

        Raises ``KeyError`` if nothing is registered for ``type``, mirroring
        dict.pop() semantics rather than silently no-opping — callers (mostly
        tests swapping the production singleton's contents) should notice if
        they try to remove something that was never there.
        """
        del self._adapters[type]

    def get(self, type):
        return self._adapters[type]

    def all(self):
        return list(self._adapters.values())

    def enabled_for(self, user):
        """Adapters this user currently holds an instance of.

        Answers "what can this user verify with right now?" — the set of
        methods to offer on a verification/challenge screen. This
        deliberately INCLUDES recovery codes: they are a valid way to prove
        identity even though they don't count as a factor in themselves.

        This is NOT the right call for deciding whether a user has MFA
        enabled / is protected — a user holding only recovery codes is not
        protected, since recovery codes are exhaustible and must never be
        someone's sole second factor. Use ``primary_enabled_for()`` for that
        question instead.
        """
        return [a for a in self.all() if a.is_enabled(user)]

    def primary_enabled_for(self, user):
        """Adapters that on their own mean this user is protected.

        Use this to decide whether to CHALLENGE a user. Use enabled_for() to
        decide what to OFFER them once challenged — that one includes recovery
        codes, which are a valid way to verify but not a factor in themselves.

        Runs one .exists() query per registered adapter (via enabled_for()),
        because it hands back actual Adapter instances. A caller that only
        needs the yes/no answer — "is this user protected at all" — should
        use has_primary_factor() below instead: same predicate, one query
        total. The two must keep agreeing, since counts_as_primary_factor is
        the single source of truth for both.
        """
        return [a for a in self.enabled_for(user) if a.counts_as_primary_factor]

    def has_primary_factor(self, user):
        """True if this user holds at least one factor that counts as
        primary — the boolean counterpart to primary_enabled_for(), for
        callers (MfaMiddleware, the enforcement decorator, the security-page
        context, the notifications module) that only need the yes/no answer
        and would otherwise pay for one .exists() query per registered
        adapter just to throw the list away.

        One query total: Authenticator.objects.filter(user=user,
        type__in=[...]).exists(). The type list is derived from the registry
        at call time (``[a.type for a in self.all() if
        a.counts_as_primary_factor]``) rather than hardcoded here, which is
        deliberate and load-bearing — Adapter.counts_as_primary_factor is the
        single, explicit source of truth for what counts as a primary
        factor (see its docstring). This project once had a second,
        independent definition of that list (models.PRIMARY_FACTOR_TYPES)
        that silently drifted out of sync with the registry and was removed
        for exactly that reason; do not reintroduce one here by hardcoding
        `type__in=["totp", "webauthn", ...]`.

        Callers that need the actual adapter list, not just whether it's
        non-empty, must keep using primary_enabled_for() instead — this
        method throws that information away by design, in exchange for the
        single query.

        signals.stamp_pending_verification and views/verify.py:verify_factor
        still call primary_enabled_for() even though both use the result as a
        bare boolean. That is not because they need the list: they run once
        per login rather than once per request, so the query saving does not
        arise there, and leaving them alone kept this change off the
        authentication path. Switching them later is safe.
        """
        types = [a.type for a in self.all() if a.counts_as_primary_factor]
        return Authenticator.objects.filter(user=user, type__in=types).exists()

    def available_for(self, user):
        """Adapters this user could add right now, via the enroll flow.

        Excludes anything that isn't enrolled at all (``supports_enroll =
        False``, i.e. recovery codes) as well as singleton factors the user
        already holds. The result is what the security page offers as "add a
        method", so every entry must be a factor ``enroll_factor`` can
        actually serve.
        """
        return [a for a in self.all()
                if a.supports_enroll and a.is_available(user)]


registry = Registry()
