"""Guard the Markdown docs against silent Sphinx misconfiguration.

The docs were converted from reStructuredText to Markdown, which means Sphinx
only understands them via myst_parser, and MyST only understands some of the
syntax they use once the matching extension is switched on.

The failure mode this exists for is specifically NOT a build error: with
`colon_fence` disabled, MyST does not complain about `:::{warning}` -- it
renders the literal text ":::{warning}" into the published page and reports
"build succeeded" with zero warnings. Watching the build output cannot catch
it. These tests read the sources instead, so they run in the ordinary suite
without Sphinx installed; CI additionally builds the docs and asserts the
admonitions become real admonition boxes.
"""

import re
import unittest
from pathlib import Path

DOCS = Path(__file__).resolve().parents[2] / "docs"


def _pages():
    return sorted(p for p in DOCS.glob("*.md"))


def _toctree_entries():
    """The document names actually listed in index.md's toctree blocks.

    Lines starting with ':' are directive options (:maxdepth:, :caption:),
    not entries.
    """
    index = (DOCS / "index.md").read_text()
    entries = set()
    for body in re.findall(r"```\{toctree\}\n(.*?)```", index, re.S):
        for line in body.splitlines():
            line = line.strip()
            if line and not line.startswith(":"):
                entries.add(line)
    return entries


def _conf_namespace():
    """Execute docs/conf.py and return the settings it actually defines.

    Deliberately NOT a text search of the file. The first version of these
    tests asserted `"colon_fence" in conf_source`, which passed even with the
    extension switched off -- because the explanatory comment above the setting
    mentions "colon_fence". Reading the evaluated values is the only check that
    distinguishes configuration from prose about configuration.
    """
    namespace = {"__file__": str(DOCS / "conf.py")}
    exec(compile((DOCS / "conf.py").read_text(), "conf.py", "exec"), namespace)
    return namespace


class DocsSourceTests(unittest.TestCase):
    def setUp(self):
        self.conf = _conf_namespace()

    def test_docs_exist_and_are_markdown(self):
        """The pages that are linked from elsewhere must not silently vanish.

        A subset check, not an equality one: adding a page should not require
        editing this test (test_every_page_is_reachable_from_the_toctree
        already covers a page being added and forgotten). Removing or
        renaming one of these DOES break links in README.md, in other pages'
        {doc} roles, or both -- so those are pinned.
        """
        names = {p.name for p in _pages()}
        expected = {
            "index.md", "installation_setup.md", "mfa_flow.md", "settings.md",
            "customizing.md", "recipes.md", "custom_factors.md", "api.md",
            "security.md", "upgrading.md", "contributing.md",
        }
        self.assertEqual(expected - names, set(),
                         "a page other docs link to has gone missing")
        self.assertEqual(list(DOCS.glob("*.rst")), [],
                         "docs are Markdown now; a stray .rst will be ignored "
                         "by the toctree and silently go unpublished")

    def test_every_setting_is_documented(self):
        """Every name in conf.DEFAULTS appears in the settings reference.

        Moved here from test_sandbox_smoke.py, which despite its name only
        ever tested this (its own docstring said so). It also read
        installation_setup.md, which stopped being the settings reference
        when that page was split -- so it would have kept passing against a
        page that no longer documented anything.
        """
        from django_mfa.conf import DEFAULTS

        reference = (DOCS / "settings.md").read_text()
        undocumented = [name for name in DEFAULTS if name not in reference]
        self.assertEqual(undocumented, [],
                         f"Undocumented settings: {undocumented}")

    def test_myst_parser_is_enabled(self):
        """Without it Sphinx finds no documents at all -- it does not read .md."""
        self.assertIn("myst_parser", self.conf.get("extensions", []))

    def test_colon_fence_enabled_if_any_page_uses_it(self):
        users = [p.name for p in _pages() if ":::{" in p.read_text()]
        if not users:
            self.skipTest("no page uses ::: directives")
        self.assertIn(
            "colon_fence", self.conf.get("myst_enable_extensions", []),
            f"{users} use ':::{{...}}' directives, but myst_enable_extensions "
            f"does not include 'colon_fence' -- MyST will render the literal "
            f"text ':::{{warning}}' into the page and still report success")

    def test_heading_anchors_enabled_if_any_page_links_to_one(self):
        """In-page links like [System checks](#system-checks) only resolve when
        myst_heading_anchors generates slugs; otherwise they are dead links
        (these do at least warn at build time)."""
        users = [p.name for p in _pages() if re.search(r"\]\(#[\w-]+\)", p.read_text())]
        if not users:
            self.skipTest("no page uses in-page anchor links")
        self.assertGreaterEqual(self.conf.get("myst_heading_anchors", 0), 2)

    def test_every_page_is_reachable_from_the_toctree(self):
        """A page missing from index.md's toctree builds fine and is simply
        never linked -- it just quietly vanishes from the published docs.

        This parses the toctree bodies rather than searching index.md for the
        page name. The substring version of this test passed with `security`
        deleted from the toctree, because index.md's own prose says "security
        keys and passkeys" -- the page name appearing *somewhere* on the page
        says nothing about whether it is actually listed.
        """
        entries = _toctree_entries()
        self.assertTrue(entries, "index.md has no toctree entries at all")
        for page in _pages():
            if page.name == "index.md":
                continue
            with self.subTest(page=page.name):
                self.assertIn(page.stem, entries)

    def test_no_leftover_rst_role_syntax(self):
        """`:doc:`x`` is reStructuredText; in Markdown it renders as literal
        text. The MyST spelling is {doc}`x`.
        """
        for page in _pages():
            with self.subTest(page=page.name):
                self.assertNotIn(":doc:`", page.read_text())

    def test_readme_carries_no_sphinx_only_syntax(self):
        """README.md is rendered by PyPI and GitHub, neither of which is
        Sphinx. A {doc} role or a ```{toctree} there does not fail the build --
        it just renders as noise on the project page.
        """
        readme = (DOCS.parent / "README.md").read_text()
        for needle in ("{doc}`", "{ref}`", "```{toctree}", ":::{"):
            self.assertNotIn(needle, readme)
