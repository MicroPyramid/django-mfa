"""Guards on the shipped templates that only a browser would otherwise catch.

Every failure pinned here renders a perfectly valid HTTP 200 that no view test
would notice, and looks broken (or silently does nothing) to a real user.
"""
import unittest
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parents[1] / "templates" / "django_mfa"


def _templates():
    return sorted(TEMPLATES.glob("*.html"))


class TemplateCommentTests(unittest.TestCase):
    def test_no_multiline_hash_comments(self):
        """`{# ... #}` is SINGLE-LINE ONLY in the Django template language.

        Spanning one across two lines does not raise, and does not comment
        anything out -- Django emits the whole thing as literal text. This was
        shipped in base.html and printed

            {# These pages are part of an authentication flow ... #}

        as the first visible line of every single MFA page. All 276 tests
        passed; it was found by loading the page in a browser.

        Use {% comment %}...{% endcomment %} for anything multi-line.
        """
        offenders = []
        for path in _templates():
            for line_no, line in enumerate(path.read_text().splitlines(), 1):
                # An opening {# whose #} is not on the same line.
                if "{#" in line and "#}" not in line[line.index("{#"):]:
                    offenders.append(f"{path.name}:{line_no}")
        self.assertEqual(
            offenders, [],
            f"multi-line {{# #}} comments render as visible page text: "
            f"{offenders}")


class WebAuthnTemplateContractTests(unittest.TestCase):
    """webauthn.js finds its elements by ID and its payload field by name.

    Dropping any of them -- easy to do while restyling -- does not error.
    The script simply never binds, and the button becomes inert: no ceremony,
    no message, nothing in the console. The page still returns 200 and still
    looks right in a screenshot.
    """

    CONTRACT = {
        "enroll_webauthn.html": "create",
        "verify_webauthn.html": "get",
    }

    def test_required_hooks_present(self):
        for name in self.CONTRACT:
            source = (TEMPLATES / name).read_text()
            for hook in ('id="webauthn-form"', 'id="webauthn-start"',
                         'id="webauthn-unsupported"', 'id="webauthn-error"',
                         'name="credential"'):
                with self.subTest(template=name, hook=hook):
                    self.assertIn(hook, source)

    def test_form_declares_the_right_ceremony_mode(self):
        """data-mode picks registration vs authentication. Swapped, the page
        runs the wrong ceremony against the right options -- and fails in a
        way that reads as a broken authenticator.
        """
        for name, mode in self.CONTRACT.items():
            with self.subTest(template=name):
                self.assertIn(f'data-mode="{mode}"',
                              (TEMPLATES / name).read_text())

    def test_options_use_the_dedicated_tag_not_json_script(self):
        """`options` is already a JSON string. Django's json_script filter
        would encode it twice, so the browser's JSON.parse() returns a string
        and options.publicKey is undefined. Server-side tests can't see it.
        """
        for name in self.CONTRACT:
            source = (TEMPLATES / name).read_text()
            with self.subTest(template=name):
                self.assertIn("webauthn_options_script", source)
                self.assertNotIn("|json_script", source)


class BaseTemplateTests(unittest.TestCase):
    def test_pages_extend_the_configured_base(self):
        """Every page must extend `base_template` (the MFA_BASE_TEMPLATE the
        views pass in), not the built-in path directly -- hardcoding it makes
        the setting silently do nothing for that page.
        """
        for path in _templates():
            if path.name == "base.html":
                continue
            with self.subTest(template=path.name):
                first = path.read_text().splitlines()[0].strip()
                self.assertEqual(first, "{% extends base_template %}")

    def test_viewport_meta_present(self):
        """Without it, mobile browsers render at ~980px and scale down: the
        pages are then technically responsive and practically unreadable.
        """
        source = (TEMPLATES / "base.html").read_text()
        self.assertIn('name="viewport"', source)
        self.assertIn("width=device-width", source)

    def test_stylesheet_is_namespaced(self):
        """static/style.css sits at the ROOT of the static namespace, where a
        host project's own style.css collides with it -- Django's
        app-directories finder resolves the clash by INSTALLED_APPS order and
        silently serves one instead of the other.
        """
        source = (TEMPLATES / "base.html").read_text()
        self.assertIn("django_mfa/style.css", source)
