"""Signals django_mfa emits, for host projects to hook.

Deliberately a separate module from django_mfa/signals.py, and deliberately
importing nothing from django_mfa. signals.py imports django_mfa.views at
module scope (for verify_rmb_cookie), so an *adapter* that imported
django_mfa.signals to send an event would close the cycle
adapters -> signals -> views -> registry -> adapters. A module with no
internal imports cannot participate in a cycle at all.

signals.py re-exports every name below, so `from django_mfa.signals import
factor_added` -- where a Django developer looks first -- also works. That
re-export is one-way (signals imports events, never the reverse) and safe.

`sender` is uniformly the Adapter *class* for the factor involved, so a
receiver can narrow with `sender=TOTPAdapter`. `request` is the request the
event happened in, or **None** when it did not happen in one: the management
commands (`mfa_reset`, `mfa_disable`) emit these too, because a factor
removed by an operator is exactly the event an audit receiver most needs to
see. Receivers must therefore tolerate `request=None` rather than reaching
straight for `request.META`. Every emission uses send_robust(), so a receiver
that does not is contained rather than breaking the action.
"""

import django.dispatch

#: A user enrolled a factor. kwargs: user, authenticator, request.
#: `authenticator` is the created Authenticator row -- every Adapter's
#: complete_enroll() returns it (see Adapter.complete_enroll's docstring).
factor_added = django.dispatch.Signal()

#: A user removed a factor. kwargs: user, factor_type, name, request.
#: The row is already gone by the time this fires, so its type and name are
#: passed by value rather than as an instance. `request` is None when a
#: management command (mfa_reset, mfa_disable) is the one removing it --
#: there is no request to pass.
factor_removed = django.dispatch.Signal()

#: A second-factor challenge succeeded. kwargs: user, method, request.
mfa_verified = django.dispatch.Signal()

#: A second-factor challenge failed. kwargs: user, method, request.
#: Fires on every failure path in views/verify.py -- a wrong code, an adapter
#: ceremony error, AND an attempt refused by the rate limiter. A receiver
#: watching for brute force needs to see the attempts that were refused, not
#: only the ones that were evaluated.
mfa_verification_failed = django.dispatch.Signal()

#: A recovery code was spent. kwargs: user, remaining, request.
#: Emitted from the adapter rather than the view: only the adapter knows how
#: many codes are left.
recovery_code_used = django.dispatch.Signal()

#: An operator granted or revoked an MFA_REQUIRED exemption.
#: kwargs: user, reason, expires_at, revoked, request.
#: sender is the MfaExemption model class -- the other five signals use the
#: Adapter subclass, and there is no adapter behind this one. Exempting
#: somebody from a security requirement is exactly as audit-worthy as
#: changing their factors, so it gets the same hook. `request` is None when
#: it comes from `manage.py mfa_disable`, which today is the only writer.
mfa_exemption_changed = django.dispatch.Signal()
