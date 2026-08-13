"""Opt-in emails telling a user their second factor changed.

Off by default (MFA_NOTIFY_ON_CHANGE). The signals in django_mfa.events fire
either way -- a project that wants delivery off the request path, or wants to
route these somewhere other than email, connects its own receiver and leaves
this switched off. That split is why the signals ship as their own module.

Templates follow the convention django-allauth established, so overriding is
familiar: shadow django_mfa/email/<event>.txt and <event>_subject.txt.
"""

import logging

from django.conf import settings as django_settings
from django.core.mail import send_mail
from django.dispatch import receiver
from django.template.loader import render_to_string

from django_mfa import events
from django_mfa.conf import settings as mfa_settings
from django_mfa.utils import user_email

logger = logging.getLogger(__name__)


def _notify(user, template, context):
    """Render and send one notification. Never raises.

    A mail outage must not turn "remove this security key I think is
    compromised" into a 500 -- the security action is more urgent than the
    message about it. Failures are logged at ERROR and dropped, which
    docs/security.md states plainly so nobody reads a delivered notification
    as a guarantee.
    """
    if not mfa_settings.MFA_NOTIFY_ON_CHANGE:
        return

    address = user_email(user)
    if not address:
        return

    try:
        subject = render_to_string(
            f"django_mfa/email/{template}_subject.txt", context)
        subject = " ".join(subject.split())
        body = render_to_string(f"django_mfa/email/{template}.txt", context)
        send_mail(
            subject, body,
            mfa_settings.MFA_FROM_EMAIL or django_settings.DEFAULT_FROM_EMAIL,
            [address],
        )
    except Exception:
        logger.exception(
            "django-mfa could not send the %r notification to user %s",
            template, getattr(user, "pk", "?"))


@receiver(events.factor_added)
def notify_factor_added(sender, user, authenticator, request=None, **kwargs):
    _notify(user, "factor_added", {
        "user": user,
        "factor": authenticator.get_type_display(),
        "name": authenticator.name,
    })


@receiver(events.factor_removed)
def notify_factor_removed(sender, user, factor_type, name, request=None,
                          **kwargs):
    # _notify() already no-ops on this setting, but checking it again here,
    # before doing anything else, matters: without this early return, every
    # factor removal -- on a default install, with notifications off -- still
    # paid for registry.has_primary_factor()'s query just to compute an
    # mfa_disabled context that _notify() would immediately discard. This is
    # what keeps a default install exactly as cheap as before notifications
    # existed at all.
    if not mfa_settings.MFA_NOTIFY_ON_CHANGE:
        return

    from django_mfa.models import Authenticator
    from django_mfa.registry import registry

    label = dict(Authenticator.Type.choices).get(factor_type, factor_type)
    _notify(user, "factor_removed", {
        "user": user, "factor": label, "name": name})

    # "I am no longer protected" is the state that matters to a user, and no
    # single signal expresses it -- it is a property of what is left, so it is
    # derived here rather than emitted as its own event. has_primary_factor,
    # not primary_enabled_for: only the yes/no answer is needed to decide
    # whether to send mfa_disabled.
    if not registry.has_primary_factor(user):
        _notify(user, "mfa_disabled", {"user": user})


@receiver(events.recovery_code_used)
def notify_recovery_code_used(sender, user, remaining, request=None, **kwargs):
    _notify(user, "recovery_code_used", {"user": user, "remaining": remaining})
