"""Guard the translation catalog and the Python strings that feed it.

Three distinct failure modes live here, none of which any other test or the
docs build would notice:

1. **A catalog that has silently rotted.** Someone adds a template string,
   never regenerates the catalog, and every translator's file is quietly
   missing an entry. Nothing errors -- gettext falls back to the English
   source -- so a half-translated page is the only symptom, and only in a
   language nobody on the team reads.

2. **An unreviewed machine draft going live.** The shipped .po files were
   machine-drafted and are marked fuzzy, which is exactly what keeps them
   inert. Strip a fuzzy flag by accident (a bulk edit, an over-eager
   `msgattrib`) and unreviewed text starts appearing in a security UI.

3. **A lazy string reaching somewhere that can't take one.** gettext_lazy
   returns a proxy, not a str. Templates resolve it, and so does
   JsonResponse -- but only because it encodes with DjangoJSONEncoder, which
   special-cases Promise. A bare json.dumps raises TypeError instead.

Extraction runs in pure Python (see tests/support/i18n.py) rather than via
`makemessages`, so these run wherever the suite runs -- gettext is not
installed in CI.
"""

import json
import re
import unittest

from django.test import SimpleTestCase
from django.utils.functional import Promise

from django_mfa.adapters.email import EmailAdapter
from django_mfa.adapters.recovery_codes import RecoveryCodesAdapter
from django_mfa.adapters.totp import TOTPAdapter
from django_mfa.adapters.webauthn import WebAuthnAdapter
from django_mfa.models import Authenticator
from django_mfa.tests.support import i18n
from django_mfa.views.verify import GENERIC_ERROR, _passkey_failure

#: Placeholders are the one thing a translator can break that crashes at
#: runtime rather than merely reading oddly: "%(code)s" renamed or dropped
#: makes the interpolation raise KeyError, in the middle of a sign-in.
PLACEHOLDER_RE = re.compile(r"%\((\w+)\)[sd]")


class CatalogCurrentTests(unittest.TestCase):
    """The committed catalog matches what the package actually contains."""

    @classmethod
    def setUpClass(cls):
        cls.extracted = i18n.extract()
        cls.pot = i18n.parse_po(i18n.LOCALE_DIR / "django.pot")
        cls.locales = i18n.locale_files()

    def test_pot_exists_and_is_not_empty(self):
        self.assertTrue(self.pot, "django.pot has no entries")

    def test_pot_matches_the_source_tree(self):
        source_keys = set(self.extracted)
        pot_keys = {i18n.po_key(e) for e in self.pot}

        missing = source_keys - pot_keys
        stale = pot_keys - source_keys
        self.assertEqual(
            (missing, stale), (set(), set()),
            "django.pot is out of date. Strings in the code but not in the "
            f"catalog: {sorted(m[1] for m in missing)}. Entries in the "
            f"catalog with no string left in the code: "
            f"{sorted(s[1] for s in stale)}. Regenerate with `makemessages`.",
        )

    def test_every_language_covers_the_whole_template(self):
        pot_keys = {i18n.po_key(e) for e in self.pot}
        self.assertTrue(self.locales, "no .po files found under locale/")
        for code, path in self.locales.items():
            with self.subTest(language=code):
                keys = {i18n.po_key(e) for e in i18n.parse_po(path)}
                self.assertEqual(
                    keys, pot_keys,
                    f"{code} does not match django.pot. Missing: "
                    f"{sorted(k[1] for k in pot_keys - keys)}. Extra: "
                    f"{sorted(k[1] for k in keys - pot_keys)}.",
                )


class DraftsStayInertTests(unittest.TestCase):
    """Nothing unreviewed reaches a user.

    Every shipped translation is machine-drafted. `fuzzy` is what makes that
    safe: gettext skips a fuzzy entry entirely and falls back to the English
    source. A language graduates by a human reviewing its entries and
    removing the flags -- at which point this test is the thing that has to
    be updated deliberately, which is the point.
    """

    def test_every_translated_entry_is_marked_fuzzy(self):
        for code, path in i18n.locale_files().items():
            with self.subTest(language=code):
                live = [e["msgid"] for e in i18n.parse_po(path)
                        if any(e["msgstrs"]) and "fuzzy" not in e["flags"]]
                self.assertEqual(
                    live, [],
                    f"{code} has non-fuzzy translations, which means they are "
                    f"live for users: {live}. Either mark them fuzzy, or -- if "
                    f"a human really has reviewed this language -- update this "
                    f"test and docs/translations.md together.",
                )

    def test_no_compiled_catalogs_are_committed(self):
        """A fully fuzzy catalog compiles to an empty one, so a .mo here is
        either dead weight or evidence something was compiled from unreviewed
        drafts. Either way it should not ship."""
        found = sorted(p.name for p in i18n.LOCALE_DIR.rglob("*.mo"))
        self.assertEqual(found, [], f"unexpected compiled catalogs: {found}")


class PlaceholderTests(unittest.TestCase):
    def test_translations_keep_every_placeholder(self):
        for code, path in i18n.locale_files().items():
            for entry in i18n.parse_po(path):
                expected = set(PLACEHOLDER_RE.findall(entry["msgid"]))
                if entry["msgid_plural"]:
                    expected |= set(PLACEHOLDER_RE.findall(entry["msgid_plural"]))
                for index, translated in enumerate(entry["msgstrs"]):
                    if not translated:
                        continue
                    with self.subTest(language=code, msgid=entry["msgid"],
                                      form=index):
                        self.assertEqual(
                            set(PLACEHOLDER_RE.findall(translated)), expected,
                            "placeholders differ from the source string, which "
                            "raises KeyError at interpolation time",
                        )


class LazyStringTests(SimpleTestCase):
    """The Python strings are translatable, and survive where they are used."""

    def test_user_facing_strings_are_lazy(self):
        lazies = {
            "GENERIC_ERROR": GENERIC_ERROR,
            "TOTPAdapter.verbose_name": TOTPAdapter.verbose_name,
            "WebAuthnAdapter.verbose_name": WebAuthnAdapter.verbose_name,
            "RecoveryCodesAdapter.verbose_name": RecoveryCodesAdapter.verbose_name,
            "EmailAdapter.verbose_name": EmailAdapter.verbose_name,
        }
        for name, value in lazies.items():
            with self.subTest(string=name):
                self.assertIsInstance(
                    value, Promise,
                    f"{name} is a plain str, so it is not translatable")

    def test_factor_type_labels_are_lazy(self):
        for choice in Authenticator.Type:
            with self.subTest(factor=choice.value):
                self.assertIsInstance(choice.label, Promise)

    def test_passkey_failure_response_serialises(self):
        """The lazy error string still reaches the client as text.

        This works because JsonResponse encodes with DjangoJSONEncoder,
        which resolves a Promise; plain json.dumps would raise TypeError and
        turn every passkey failure -- the ordinary wrong-credential path,
        not an edge case -- into a 500 instead of the deliberately uniform
        400. Asserting the decoded body rather than the encoder keeps this
        honest if the response is ever built a different way.
        """
        response = _passkey_failure()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content),
                         {"error": "Passkey sign-in failed."})

    def test_factor_labels_still_render_as_text(self):
        """get_type_display() feeds email templates; a proxy must format."""
        authenticator = Authenticator(type=Authenticator.Type.TOTP)
        self.assertEqual(f"{authenticator.get_type_display()}",
                         "Authenticator app")
