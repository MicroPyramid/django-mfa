"""Guard the translation catalog and the Python strings that feed it.

Three distinct failure modes live here, none of which any other test or the
docs build would notice:

1. **A catalog that has silently rotted.** Someone adds a template string,
   never regenerates the catalog, and every translator's file is quietly
   missing an entry. Nothing errors -- gettext falls back to the English
   source -- so a half-translated page is the only symptom, and only in a
   language nobody on the team reads.

2. **A translation that never reaches anyone.** The catalogs are live now,
   and Django reads *only* compiled .mo files. A .po edited without
   rerunning `tools/compile_catalogs.py` therefore changes nothing at all:
   it looks right in the diff, it looks right in review, and the user keeps
   seeing the old text -- or English.

3. **A lazy string reaching somewhere that can't take one.** gettext_lazy
   returns a proxy, not a str. Templates resolve it, and so does
   JsonResponse -- but only because it encodes with DjangoJSONEncoder, which
   special-cases Promise. A bare json.dumps raises TypeError instead.

Extraction runs in pure Python (see tests/support/i18n.py) rather than via
`makemessages`, so these run wherever the suite runs -- gettext is not
installed in CI.
"""

import gettext
import importlib
import json
import re
import unittest
from pathlib import Path

from django.test import SimpleTestCase
from django.utils import translation
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


class LiveCatalogTests(unittest.TestCase):
    """Every shipped language is complete and compiled.

    These catalogs are live: no entry is fuzzy, so what is in them is what
    users of that language see. Two things can quietly break that, and
    neither raises anywhere on its own:

    * A half-translated language. An entry with an empty msgstr falls back to
      English, so the page renders in two languages at once and nothing
      errors.
    * A .po edited without recompiling. Django reads only .mo files, so the
      edit changes precisely nothing -- the reviewer sees their fix in the
      diff, and the user never sees it at all.
    """

    def test_every_entry_is_translated(self):
        for code, path in i18n.locale_files().items():
            with self.subTest(language=code):
                untranslated = [e["msgid"] for e in i18n.parse_po(path)
                                if not all(e["msgstrs"])]
                self.assertEqual(
                    untranslated, [],
                    f"{code} has entries with no translation, which render in "
                    f"English beside translated text: {untranslated}",
                )

    def test_no_entry_is_still_fuzzy(self):
        """fuzzy is how a draft is kept inert; these are no longer drafts.

        A fuzzy entry is skipped by gettext AND dropped by compile_mo(), so
        one left behind here is an invisible hole in an otherwise live
        language rather than an error anybody would see.
        """
        for code, path in i18n.locale_files().items():
            with self.subTest(language=code):
                fuzzy = [e["msgid"] for e in i18n.parse_po(path)
                         if "fuzzy" in e["flags"]]
                self.assertEqual(fuzzy, [], f"{code} has fuzzy entries: {fuzzy}")

    def test_compiled_catalogs_are_current(self):
        """Each .mo is exactly what its .po compiles to, right now.

        This is the guard for the failure mode above: edit a .po, forget
        `tools/compile_catalogs.py`, ship a translation nobody receives.
        """
        for code, po in i18n.locale_files().items():
            with self.subTest(language=code):
                mo = i18n.mo_path(po)
                self.assertTrue(
                    mo.exists(),
                    f"{code} has no compiled catalog; Django reads only .mo "
                    f"files, so this language is not actually translated. "
                    f"Run `python tools/compile_catalogs.py`.")
                self.assertEqual(
                    mo.read_bytes(), i18n.compile_mo(po),
                    f"{code}.mo is stale -- its .po has changed since it was "
                    f"compiled. Run `python tools/compile_catalogs.py`.")


class DjangoServesTranslationsTests(SimpleTestCase):
    """The compiled catalogs work through Django, not just on paper.

    Everything above reads the catalogs with this project's own code, which
    cannot catch a malformed .mo: compile_mo() would have to be wrong in the
    same way twice. This reads them back through Django (and so through the
    standard library's gettext.GNUTranslations, an implementation nothing
    here had a hand in), which is also the exact path a request takes.
    """

    def test_django_serves_every_language(self):
        for code, path in i18n.locale_files().items():
            # Django normalises locale names ("pt_BR" -> "pt-br"); its
            # override() wants the language code, the directory is named for
            # the locale.
            language = code.lower().replace("_", "-")
            for entry in i18n.parse_po(path):
                with self.subTest(language=code, msgid=entry["msgid"]):
                    with translation.override(language):
                        if entry["msgctxt"] is not None:
                            self.assertEqual(
                                translation.pgettext(
                                    entry["msgctxt"], entry["msgid"]),
                                entry["msgstrs"][0])
                            continue
                        if entry["msgid_plural"] is None:
                            self.assertEqual(
                                translation.gettext(entry["msgid"]),
                                entry["msgstrs"][0])
                            continue
                        # n=1 selects form 0 under every plural rule these
                        # six languages use. At n=2 the two-form languages
                        # move to form 1 while the one-form languages (ja,
                        # zh_Hans) stay on form 0 -- which is what the
                        # length of msgstrs tells us.
                        self.assertEqual(
                            translation.ngettext(
                                entry["msgid"], entry["msgid_plural"], 1),
                            entry["msgstrs"][0])
                        self.assertEqual(
                            translation.ngettext(
                                entry["msgid"], entry["msgid_plural"], 2),
                            entry["msgstrs"][-1])


class MsgidCollisionTests(SimpleTestCase):
    """No bare msgid of ours is one a bundled Django app also translates.

    gettext keys on the string itself, and Django merges every app's catalog
    into one per language. `_add_installed_apps_translations` merges
    ``reversed(app_configs)``, so the app listed FIRST in INSTALLED_APPS is
    merged LAST and wins any key two apps share. `django.contrib.admin` is
    listed first in almost every project.

    The result is invisible: the page renders, in the right language, using
    another app's wording -- and only in the languages that app happens to
    translate, so it cannot be caught by reading the English UI. `Remove`
    was exactly this, silently served as admin's `Enlever`/`删除` rather
    than ours, until it was given a context.

    A generic new string ("Save", "Close", "Yes", "Delete") reintroduces the
    problem, which is why this is a test and not a note. The fix is never to
    reword around admin -- it is to add a ``context``, which makes the key
    ours alone.
    """

    #: The apps a host project realistically has installed alongside this
    #: one. django.conf's own catalog is the base layer under all of them.
    BUNDLED = [
        "django.conf", "django.contrib.admin", "django.contrib.admindocs",
        "django.contrib.auth", "django.contrib.contenttypes",
        "django.contrib.flatpages", "django.contrib.humanize",
        "django.contrib.messages", "django.contrib.postgres",
        "django.contrib.redirects", "django.contrib.sessions",
        "django.contrib.sites",
    ]

    @staticmethod
    def _bundled_msgids(module_name, language):
        module = importlib.import_module(module_name)
        mo = (Path(module.__file__).parent / "locale" / language
              / "LC_MESSAGES" / "django.mo")
        if not mo.exists():
            return set()
        with mo.open("rb") as handle:
            catalog = gettext.GNUTranslations(handle)._catalog
        # Plural entries are keyed (msgid, index) tuples; only bare string
        # keys can collide with a bare msgid of ours.
        return {key for key in catalog if isinstance(key, str)}

    def test_no_bare_msgid_collides_with_a_bundled_app(self):
        ours = {entry["msgid"] for path in i18n.locale_files().values()
                for entry in i18n.parse_po(path)
                if entry["msgctxt"] is None}
        for language in i18n.locale_files():
            for module_name in self.BUNDLED:
                try:
                    theirs = self._bundled_msgids(module_name, language)
                except ImportError:
                    continue    # optional app (psycopg for contrib.postgres)
                clashing = sorted(ours & theirs)
                with self.subTest(language=language, app=module_name):
                    self.assertEqual(
                        clashing, [],
                        f"{module_name} also translates {clashing} into "
                        f"{language}, and wins the key whenever it is listed "
                        f"before django_mfa in INSTALLED_APPS. Give ours a "
                        f'{{% trans "..." context "..." %}} so the key is ours.',
                    )


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
