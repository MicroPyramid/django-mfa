"""Sphinx configuration.

Replaces a 579-line sphinx-quickstart dump in which the ENTIRE config block
appeared twice (so the second copy silently won), 503 of those lines were
commented-out boilerplate, and `version`/`release` still read "2.1" long
after the package reached 4.0.0a1.

The version is now read from the installed package metadata, so it cannot
drift from pyproject.toml again.
"""

from importlib.metadata import PackageNotFoundError, version as _version

project = "django-mfa"
author = "Micro Pyramid"
copyright = f"2016-2026, {author}"  # noqa: A001 -- Sphinx requires this name

try:
    release = _version("django-mfa")
except PackageNotFoundError:  # docs built from a source checkout
    release = "0.0.0.dev0"
version = release

# The docs are Markdown, not reStructuredText. Sphinx cannot read Markdown on
# its own -- myst_parser is what registers the .md suffix and the MyST syntax
# the pages use ({doc} roles for cross-references, ```{toctree} / :::{warning}
# fenced directives). Without it, `sphinx-build` finds no documents at all.
#
# sphinx.ext.autodoc used to be listed here and was never used by a single
# page -- no automodule/autoclass/autofunction directive existed anywhere. It
# is deliberately not re-added: the public API is documented by hand in
# api.md, so the docs describe the surface host projects should actually
# depend on rather than everything that happens to be importable. Adding
# autodoc back would also mean running django.setup() in this file, since
# importing django_mfa.models without configured settings raises
# ImproperlyConfigured.
# sphinx_design supplies the landing page's cards and the pip/uv tabs, and
# sphinx_copybutton puts a copy button on every code block. Both are docs-group
# dependencies only; nothing here is imported by the package.
extensions = ["myst_parser", "sphinx_design", "sphinx_copybutton"]

# Generate anchor slugs for headings down to level 3, so in-page links like
# [System checks](#system-checks) resolve. The pages carry several of these,
# converted from reStructuredText internal references; without this they build
# as "cross-reference target not found" warnings and render as dead links.
myst_heading_anchors = 3

# colon_fence enables `:::{warning}` ... `:::` directives. Without it MyST does
# NOT error -- it renders the literal text ":::{warning}" into the page and the
# build still reports success, so this cannot be caught by watching for
# warnings. django_mfa/tests/test_docs.py pins the setting; the `docs` CI job
# builds the pages and asserts the admonitions become real admonition boxes.
# tasklist turns "- [ ]" lines into checkboxes, which security.md's production
# checklist uses; without it they render as a literal "[ ]".
myst_enable_extensions = ["colon_fence", "tasklist"]

# "superpowers" used to be excluded here: internal spec/plan artifacts lived
# in docs/superpowers/. They now live in .superpowers/ at the repo root,
# outside the docs tree entirely, so there is nothing left to exclude but the
# build output.
exclude_patterns = ["_build"]
language = "en"

# Every code block names its language, so nothing should fall through to a
# guess. "none" makes an unlabelled block plain text rather than Python.
highlight_language = "none"

html_theme = "furo"
html_title = "django-mfa"
htmlhelp_basename = "django-mfa"
html_static_path = ["_static"]
html_css_files = ["custom.css"]
html_logo = "_static/logo.svg"
html_favicon = "_static/logo.svg"

_GITHUB = "https://github.com/MicroPyramid/django-mfa"
html_theme_options = {
    "source_repository": _GITHUB,
    "source_branch": "master",
    "source_directory": "docs/",
    "top_of_page_buttons": ["view", "edit"],
    "light_css_variables": {
        "color-brand-primary": "#0c4b33",
        "color-brand-content": "#0c6e4a",
        "color-brand-visited": "#0c6e4a",
    },
    "dark_css_variables": {
        "color-brand-primary": "#5fd4a0",
        "color-brand-content": "#5fd4a0",
        "color-brand-visited": "#5fd4a0",
    },
    "footer_icons": [
        {
            "name": "GitHub",
            "url": _GITHUB,
            "html": (
                '<svg stroke="currentColor" fill="currentColor" stroke-width="0" '
                'viewBox="0 0 16 16"><path fill-rule="evenodd" d="M8 0C3.58 0 0 '
                "3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 "
                "0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94"
                "-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 "
                "1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 "
                "0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82"
                ".64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 "
                "2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 "
                "3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 "
                ".21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z\"></path></svg>"
            ),
            "class": "",
        },
    ],
}

# Shell blocks are written without a "$ " prompt, but strip one if a page
# ever adds it, so the copied text still runs as pasted.
copybutton_prompt_text = r"\$ |>>> "
copybutton_prompt_is_regexp = True

