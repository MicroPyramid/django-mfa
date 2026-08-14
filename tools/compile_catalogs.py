"""Refresh and compile django-mfa's translation catalogs.

    uv run python tools/compile_catalogs.py

This is `makemessages --no-obsolete` plus `msgfmt`, in pure Python, doing the
two jobs those would do here:

1. **Refresh source references.** The ``#:`` lines above each entry say where
   in the code the string lives. They are the only part of a catalog derived
   from the source rather than from a translator, and they go stale silently
   every time a template gains a line above an existing string.

2. **Compile.** Django reads *only* ``.mo`` files. A ``.po`` edited and not
   compiled changes nothing at all a user can see: it looks right in the
   diff, it looks right in review, and the old text keeps being served.

Translations themselves are carried over verbatim -- this never invents,
reorders or drops one. Adding or removing a *string* still means editing the
catalogs by hand; see docs/translations.md.

It exists because gettext's binaries are a system package this project
declines to require of anyone (the same constraint that produced the
extractor in django_mfa/tests/support/i18n.py, which holds the actual
implementation and explains both formats).

Not part of the distributed package: the built wheel ships the generated
catalogs, not this script.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import django  # noqa: E402  (all three need the path inserted above)
from django.conf import settings  # noqa: E402

# templatize() reaches for the template engine settings, so Django has to be
# configured before django_mfa.tests.support.i18n is imported at all.
if not settings.configured:
    settings.configure(INSTALLED_APPS=["django_mfa"], USE_I18N=True)
    django.setup()

from django_mfa.tests.support import i18n  # noqa: E402


def main():
    catalogs = i18n.locale_files()
    if not catalogs:
        print("No .po files found under django_mfa/locale/.", file=sys.stderr)
        return 1

    references = {key: [f"{path}:{line}" for path, line in refs]
                  for key, refs in i18n.extract().items()}

    # The .pot carries references too, and is the file a new translation is
    # started from, so it goes stale the same way and is refreshed the same
    # way. It has no compiled form -- it is a template, not a catalog.
    for path in [i18n.LOCALE_DIR / "django.pot", *catalogs.values()]:
        before = path.read_bytes()
        i18n.write_po(path, i18n.po_comment(path), i18n.po_header(path),
                      i18n.parse_po(path), references)
        if path.read_bytes() != before:
            print(f"{path.relative_to(i18n.REPO_ROOT)}: references refreshed")

    for language, po in sorted(catalogs.items()):
        mo = i18n.mo_path(po)
        data = i18n.compile_mo(po)
        # Compared before writing so a no-op run says so: a silent "wrote 6
        # files" makes a real regeneration indistinguishable from an
        # accidental one.
        changed = not mo.exists() or mo.read_bytes() != data
        mo.write_bytes(data)
        print(f"{language:>8}: {len(data):>6} bytes"
              f"{'  (changed)' if changed else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
