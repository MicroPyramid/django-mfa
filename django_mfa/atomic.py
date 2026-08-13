# django_mfa/atomic.py
#
# Race-free updates to an Authenticator's `data` JSON blob.
#
# Every factor that consumes something one-time-only keeps that state inside
# `Authenticator.data`: the TOTP counter that was last accepted, the recovery
# codes already spent, the WebAuthn signature counter. All three were written
# as a plain read-modify-write --
#
#     row = ...get()
#     row.data["used"].append(i)
#     row.save(update_fields=["data"])
#
# -- which is a lost update under concurrency. Two simultaneous POSTs both
# read the pre-update blob, both decide the credential is unspent, and the
# second save() overwrites the first. That is not a theoretical concern for
# this package specifically: it defeats the single-use guarantee that is the
# entire security property of a recovery code (docs/security.md) and of
# WebAuthn clone detection, and it lets one TOTP code be redeemed twice.
#
# `select_for_update()` is the usual Django answer and is deliberately NOT
# used here: Django's SQLite backend sets has_select_for_update = False, so it
# is silently a no-op there, and a lock that quietly does nothing on one of
# the supported backends is worse than no lock at all.
#
# Instead this is an optimistic compare-and-set: read the blob, compute the
# new one, then UPDATE ... WHERE data = <the blob we read>. That WHERE clause
# is a plain JSONField exact match, which every backend Django supports can
# evaluate (jsonb equality on PostgreSQL, text equality elsewhere), so it
# behaves identically everywhere including SQLite. A caller that loses the
# race matches zero rows, re-reads, and re-applies on top of the winner.
import copy

#: Attempts before giving up. Each retry only happens when another writer
#: committed to the same row in the microseconds between this one's SELECT and
#: its UPDATE, so anything beyond a couple is already pathological; the bound
#: exists so a permanently-contended row can never spin forever inside a
#: request. Exhausting it returns False, which every caller treats as "this
#: verification did not succeed" -- fail closed.
MAX_ATTEMPTS = 5


def update_data(authenticator, apply):
    """Atomically transform ``authenticator.data``.

    ``apply`` is called with the blob as currently committed (never the
    caller's possibly-stale in-memory copy) and returns either the new blob
    or ``None`` to decline. Declining is how a caller says "having now seen
    the real current state, this attempt is not valid after all" -- e.g. a
    recovery code that a concurrent request consumed first.

    Returns True only if a write actually landed, in which case
    ``authenticator.data`` is updated in place to match. Returns False if
    ``apply`` declined, if the row has been deleted, or if this caller lost
    the race ``MAX_ATTEMPTS`` times.
    """
    model = type(authenticator)
    for _ in range(MAX_ATTEMPTS):
        current = model.objects.filter(pk=authenticator.pk).values_list(
            "data", flat=True).first()
        if current is None:
            # The row was deleted -- e.g. the user removed this authenticator
            # from another tab while this verification was in flight. There is
            # nothing left to consume.
            return False

        # deepcopy so a caller that mutates the dict it is handed (rather than
        # building a new one) cannot corrupt the value used in the WHERE
        # clause, which must stay exactly what was read.
        new_data = apply(copy.deepcopy(current))
        if new_data is None:
            return False

        updated = model.objects.filter(
            pk=authenticator.pk, data=current).update(data=new_data)
        if updated:
            authenticator.data = new_data
            return True
    return False
