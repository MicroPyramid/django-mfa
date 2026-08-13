# django_mfa/templatetags/webauthn_tags.py
"""Template tag for safely embedding WebAuthn ceremony options in a page.

``WebAuthnAdapter.begin_enroll()``/``begin_verify()`` (django_mfa/adapters/
webauthn.py) hand the enroll/verify views a context key ``"options"`` that
is already a JSON-encoded *string* -- ``json.dumps(dict(options))`` -- not a
plain Python object. Piping that string straight through Django's built-in
``json_script`` filter (``{{ options|json_script:"webauthn-options" }}``)
would double-encode it: ``json.dumps()`` of a string wraps it in an extra
pair of quotes and escapes the embedded quotes, so the single
``JSON.parse()`` call in webauthn.js would hand back the *original JSON
text as a JS string* instead of the options object, and
``options.publicKey`` would be ``undefined`` -- a bug that only shows up in
a real browser, never in a Python test that stops at "did the page render".

This tag undoes that: it decodes the string back into a Python object with
``json.loads`` and then calls Django's own ``django.utils.html.json_script``
-- the exact function backing the ``json_script`` filter -- to do the real
HTML-safe escaping and ``<script type="application/json">`` wrapping.
Nothing here re-implements escaping by hand.
"""
import json

from django import template
from django.utils.html import json_script as html_json_script

register = template.Library()


@register.simple_tag(name="webauthn_options_script")
def webauthn_options_script(options_json, element_id):
    """Safely render a pre-serialized options JSON string into a
    ``<script type="application/json" id="{element_id}">`` block.

    ``options_json`` is the JSON *string* produced by
    ``WebAuthnAdapter.begin_enroll()``/``begin_verify()``; this parses it
    back into a Python object before handing it to Django's ``json_script``
    so the value is escaped exactly once, not twice.
    """
    return html_json_script(json.loads(options_json), element_id)
