"""Template tags for rendering django-mfa templates.

The previous ``qrcode`` filter pointed the browser straight at
``chart.apis.google.com`` -- a chart-rendering service Google decommissioned
years ago. Every TOTP enrollment page therefore showed a broken image and no
user could actually scan a code. This renders the QR code as an SVG entirely
on the server and inlines it as a base64 data URI instead, so enrollment
never depends on any third-party host being reachable (or even existing).

SVG rather than PNG because ``qrcode``'s ``SvgPathImage`` factory needs only
the standard library. PNG output would require Pillow (a large dependency
with C build requirements, for one image on one page) or a hand-rolled binary
image encoder (bespoke compression/checksum/chunk-packing code inside an auth
library). SVG scales crisply and is supported by every browser that supports
WebAuthn.
"""
import base64
import io

import qrcode as qrcode_lib
import qrcode.image.svg as qrcode_svg
from django import template
from django.utils.html import conditional_escape, format_html

from django_mfa.utils import mask_email as _mask_email

register = template.Library()


@register.filter(name="mask_email")
def mask_email(address):
    """Expose django_mfa.utils.mask_email() as a filter.

    security.html uses this to show which mailbox an email-type
    Authenticator row is bound to (masked, not the full address) --
    docs/settings.md promises this and, until this filter existed, the
    template had no way to keep that promise: authenticator.name is
    WebAuthn-only and always blank for an emailed-code row.
    """
    return _mask_email(address)


@register.simple_tag(name="qrcode")
def qrcode(value, alt=None):
    """Render an OTP provisioning URI as an inline SVG ``<img>``."""
    img = qrcode_lib.make(value, image_factory=qrcode_svg.SvgPathImage)
    buffer = io.BytesIO()
    img.save(buffer)
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return format_html(
        '<img class="qrcode" src="data:image/svg+xml;base64,{}" alt="{}">',
        encoded, conditional_escape(alt or "Scan this code"),
    )
