"""What must happen, and in what order, for one enrollment or verification.

Two view layers drive the same factors: the HTML views (``django_mfa/views/``)
and the JSON API (``django_mfa/api/``). They differ only in how a result is
rendered -- a redirect and a template versus a status code and a body -- and
that difference is all either of them should contain.

Everything else is here, once. The ordering below is not incidental; each
step is load-bearing, and the failure modes if a second copy drifts are the
quiet kind:

* **Rate-limit check before the adapter, always.** Skip it in one layer and
  that layer is an unmetered oracle for every factor.
* **Every failed attempt records a failure**, including one caused by a
  malformed payload rather than a wrong code. A layer that records only
  "wrong code" lets an attacker spend unlimited attempts by malforming them.
* **Clear the counter only on success**, and mark the session verified only
  after the adapter has said yes.
* **Emit the event even for an attempt the limiter refused.** A brute-force
  detector needs the refused attempts most of all -- see events.py.

Nothing here renders, and nothing here decides *whether* a caller is allowed
to make the attempt: authentication, step-up freshness and the enrolled-vs-
pending distinction all belong to the view layer, which is where the two
layers legitimately differ.
"""

from django_mfa import events, ratelimit, session
from django_mfa.registry import registry


class FactorRejected(Exception):
    """An enrollment the adapter refused.

    Normalises the three exception types an adapter may raise -- ValueError
    (a wrong code, a stale ceremony), TypeError (a payload that is valid
    JSON but the wrong shape) and KeyError (a missing field) -- into one, so
    that no view layer has to remember all three and none of them can leak
    which check failed by handling one differently from the others.
    """


def attempt_verify(request, user, factor_type, data):
    """Run one verification attempt. True if the session is now verified.

    ``data`` is any mapping the adapter understands -- ``request.POST`` from
    a form, a decoded JSON body from the API.
    """
    adapter = registry.get(factor_type)

    # A locked-out attempt is never evaluated, and gets exactly the response
    # a wrong code gets, so that the lockout is not itself an oracle. That
    # sameness is the caller's job to preserve; this returns False for both.
    allowed = ratelimit.check(user, factor_type)
    verified = False
    if allowed:
        try:
            verified = adapter.complete_verify(request, user, data)
        except (ValueError, TypeError, KeyError):
            # Clone detection (ValueError), a tampered credential payload
            # (TypeError out of fido2 parsing a non-mapping), or a missing
            # field (KeyError). All three must be indistinguishable from an
            # ordinary wrong code -- to the caller AND to the rate limiter,
            # which is why this falls through rather than returning early.
            verified = False

    if verified:
        ratelimit.clear(user, factor_type)
        session.mark_verified(request, factor_type)
        events.mfa_verified.send_robust(
            sender=type(adapter), user=user, method=factor_type,
            request=request)
        return True

    if allowed:
        # Budget accounting: only an attempt that was actually evaluated
        # spends from the budget.
        ratelimit.record_failure(user, factor_type)
    # An observation, not accounting -- so it fires either way, including
    # for the attempt the limiter refused.
    events.mfa_verification_failed.send_robust(
        sender=type(adapter), user=user, method=factor_type, request=request)
    return False


def attempt_enroll(request, factor_type, data):
    """Complete one enrollment. Returns the created ``Authenticator``.

    Raises ``FactorRejected`` if the adapter refuses the submission.

    Deliberately not rate-limited, unlike attempt_verify: the code checked
    here is checked against a secret the caller supplied in the same request
    (TOTP's ``secret_key``, WebAuthn's ceremony state), so there is nothing
    an attacker could brute-force but their own value.

    Enrolling marks the session verified -- the user just proved possession
    of the factor. That is exactly why the enroll and verify exempt sets in
    MfaMiddleware must stay separate: a *pending* user let onto an enrollment
    path could satisfy their session with a factor of their own choosing
    instead of the one they already hold.
    """
    adapter = registry.get(factor_type)
    try:
        authenticator = adapter.complete_enroll(request, data)
    except (ValueError, TypeError, KeyError) as exc:
        raise FactorRejected(factor_type) from exc

    session.mark_verified(request, factor_type)
    events.factor_added.send_robust(
        sender=type(adapter), user=request.user,
        authenticator=authenticator, request=request)
    return authenticator


def remove_factor(request, authenticator):
    """Delete one enrolled factor and announce it.

    Takes the type and name before deleting, because both are wanted by the
    signal and neither survives the delete.
    """
    factor_type, name = authenticator.type, authenticator.name
    authenticator.delete()
    try:
        sender = type(registry.get(factor_type))
    except KeyError:
        # A row whose type is no longer registered (MFA_FACTORS narrowed, or
        # registry.unregister()). Removing one is a supported action and must
        # not raise after the delete has already committed; there is simply
        # no adapter class to name as the sender.
        sender = None
    events.factor_removed.send_robust(
        sender=sender, user=request.user, factor_type=factor_type,
        name=name, request=request)
