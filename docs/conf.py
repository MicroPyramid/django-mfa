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
extensions = ["myst_parser"]

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
myst_enable_extensions = ["colon_fence"]

# "superpowers" used to be excluded here: internal spec/plan artifacts lived
# in docs/superpowers/. They now live in .superpowers/ at the repo root,
# outside the docs tree entirely, so there is nothing left to exclude but the
# build output.
exclude_patterns = ["_build"]
language = "en"

html_theme = "sphinx_rtd_theme"
htmlhelp_basename = "django-mfa"

# No templates_path/html_static_path: docs/_templates and docs/_static never
# existed, and naming a directory that isn't there is a build warning.

