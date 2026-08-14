"""Extract translatable strings and read PO catalogs, without gettext.

`makemessages` shells out to xgettext, which is a system package this test
suite cannot assume: it is absent from this project's CI images and from at
least one maintainer's machine. A catalog guard that silently skips wherever
gettext is missing guards nothing -- it would have been skipped in every
environment that actually runs the suite, which is the same shape of failure
`test_packaging.py` exists to prevent (a green tick over a check that never
ran).

So extraction happens in pure Python here instead:

* Templates go through ``django.utils.translation.template.templatize()``,
  the exact function `makemessages` itself feeds to xgettext. It rewrites a
  Django template into a Python-ish source where every translatable string
  appears as a ``gettext(...)`` call and *all* other content -- including
  quote characters -- is replaced by filler letters, preserving line and
  column positions. That output is deliberately not valid Python (``ast``
  chokes on it), which is why the calls are found by regex, the way
  xgettext's own lenient lexer does. The filler guarantee is what makes the
  regex safe: a string literal in that output can only have come from a real
  translation tag.

* Python modules are parsed with ``ast``, which is exact.

This module is test support, not shipped API. Nothing in django_mfa imports
it.
"""

import ast
import re
import struct
from pathlib import Path

from django.utils.translation.template import templatize

PACKAGE = Path(__file__).resolve().parents[2]
REPO_ROOT = PACKAGE.parent
LOCALE_DIR = PACKAGE / "locale"

#: The gettext family Django's template lexer emits, plus the aliases the
#: Python side uses. `_` is included because that is how django_mfa imports
#: gettext_lazy.
GETTEXT_NAMES = frozenset({
    "_", "gettext", "gettext_lazy", "gettext_noop",
    "ngettext", "ngettext_lazy",
    "pgettext", "pgettext_lazy", "npgettext", "npgettext_lazy",
})

_CALL_RE = re.compile(r"\b(?P<fn>n?p?gettext(?:_lazy|_noop)?)\s*\(")
_STR_RE = re.compile(
    r"""[ubUB]*(?P<q>'''|\"\"\"|'|")(?P<body>(?:\\.|(?!(?P=q))[\s\S])*)(?P=q)""")


def _string_run(source, pos):
    """Consecutive comma-separated string literals starting at ``pos``.

    Stops at the first argument that is not a literal, which is how the
    count argument of ngettext() and the context of pgettext() are handled:
    a context is a literal and so is collected, a count is not and so ends
    the run.
    """
    literals = []
    while True:
        match = _STR_RE.match(source, pos)
        if not match:
            break
        literals.append(ast.literal_eval(match.group(0)))
        pos = match.end()
        while pos < len(source) and source[pos] in " \t":
            pos += 1
        if pos >= len(source) or source[pos] != ",":
            break
        pos += 1
        while pos < len(source) and source[pos] in " \t":
            pos += 1
    return literals


def _key_from_call(name, literals):
    """Turn one gettext-family call into a catalog key.

    The key is ``(msgctxt, msgid, msgid_plural)`` with None for the parts a
    given call shape doesn't carry. Getting this right is the difference
    between a usable catalog and a broken one: an ``ngettext`` pair recorded
    as two independent singular entries produces msgids gettext will never
    look up at runtime, because a plural lookup is keyed on the singular AND
    the plural together.

    Returns None for a call with no literal msgid -- ``_(variable)`` is
    legal Python that xgettext also declines to extract.
    """
    base = name.removesuffix("_lazy").removesuffix("_noop")
    has_context = base.startswith("p") or base.startswith("np")
    is_plural = base.startswith("n")

    context = None
    if has_context:
        if not literals:
            return None
        context, literals = literals[0], literals[1:]
    if not literals:
        return None
    if is_plural:
        if len(literals) < 2:
            return None
        return (context, literals[0], literals[1])
    return (context, literals[0], None)


def strings_in_template(path):
    """[(key, line number)] for one template file."""
    source = templatize(path.read_text(encoding="utf-8"), origin=str(path))
    found = []
    for match in _CALL_RE.finditer(source):
        line = source.count("\n", 0, match.start()) + 1
        key = _key_from_call(match.group("fn"), _string_run(source, match.end()))
        if key is not None:
            found.append((key, line))
    return found


def strings_in_python(path):
    """[(key, line number)] for one Python module."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = getattr(func, "id", None) or getattr(func, "attr", None)
        if name not in GETTEXT_NAMES:
            continue
        literals = []
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                literals.append(arg.value)
            else:
                # A non-literal argument ends the run for the same reason as
                # in _string_run: it is a count or an interpolation target,
                # not something a translator can be handed.
                break
        # `_` is an alias for gettext_lazy throughout this package; the
        # regex-driven template path never sees it, so it is normalised here.
        key = _key_from_call("gettext" if name == "_" else name, literals)
        if key is not None:
            found.append((key, node.lineno))
    return found


def source_files():
    """Every file in the package that can hold a translatable string.

    Tests are excluded: their strings are fixtures, and a translator being
    asked to translate an assertion message would be a bug in this list.
    """
    templates = sorted(
        p for p in (PACKAGE / "templates").rglob("*") if p.is_file())
    modules = sorted(
        p for p in PACKAGE.rglob("*.py")
        if "tests" not in p.relative_to(PACKAGE).parts
    )
    return templates, modules


def extract():
    """Every translatable string in the package.

    Returns ``{(msgctxt, msgid, msgid_plural): [(repo-relative path, line)]}``
    with keys and references sorted, so the result is stable enough both to
    write a .pot from and to compare a committed .pot against.
    """
    templates, modules = source_files()
    catalog = {}
    for path, reader in (
        *((p, strings_in_template) for p in templates),
        *((p, strings_in_python) for p in modules),
    ):
        for key, line in reader(path):
            rel = path.relative_to(REPO_ROOT).as_posix()
            catalog.setdefault(key, []).append((rel, line))
    return {
        key: sorted(set(refs))
        # Sort on the string parts only: None is not orderable against str,
        # so a plain sorted() on the keys breaks the moment a context or a
        # plural appears alongside an entry without one.
        for key, refs in sorted(catalog.items(), key=lambda kv: tuple(
            part or "" for part in kv[0]))
    }


# --- PO files ---------------------------------------------------------------

def po_escape(value):
    return (value.replace("\\", "\\\\").replace('"', '\\"')
                 .replace("\n", "\\n").replace("\t", "\\t"))


def po_unescape(value):
    out, i = [], 0
    simple = {"n": "\n", "t": "\t", '"': '"', "\\": "\\"}
    while i < len(value):
        char = value[i]
        if char == "\\" and i + 1 < len(value):
            out.append(simple.get(value[i + 1], value[i + 1]))
            i += 2
        else:
            out.append(char)
            i += 1
    return "".join(out)


def _blank_entry():
    return {"msgctxt": None, "msgid": None, "msgid_plural": None,
            "msgstrs": [], "flags": set()}


def parse_po(path):
    """Minimal PO reader, returning one dict per entry with the header dropped.

    Each entry carries ``msgctxt``, ``msgid``, ``msgid_plural``, ``msgstrs``
    (a list -- one item for a singular entry, nplurals items for a plural
    one) and ``flags``.

    Deliberately not a general-purpose PO parser: it understands exactly the
    subset this project's catalogs use, which is also the subset
    tools/compile_catalogs.py consumes. It judges nothing -- the tests do
    that.
    """
    entries, current, field = [], _blank_entry(), None
    # Flags and msgctxt both PRECEDE the entry they belong to ("#, fuzzy"
    # and `msgctxt "..."` sit above the msgid), so both are buffered and
    # attached to the NEXT entry. Writing either into `current` as it is
    # read files it against the preceding entry instead -- which for a
    # context is doubly wrong, because it also leaves the entry that really
    # has one looking uncontexted, and the two errors cancel out into a
    # catalog that merely looks shifted by one rather than obviously broken.
    pending_flags = set()
    pending_ctxt = None

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#,"):
            pending_flags |= {f.strip() for f in line[2:].split(",")}
            continue
        if line.startswith("#"):
            continue

        match = re.match(r"(msgctxt|msgid_plural|msgid|msgstr(?:\[(\d+)\])?)\s+"
                         r'"(.*)"$', line)
        if match:
            keyword, _index, value = match.groups()
            value = po_unescape(value)
            if keyword == "msgid":
                if current["msgid"]:
                    entries.append(current)
                current = _blank_entry()
                current["flags"], pending_flags = pending_flags, set()
                current["msgctxt"], pending_ctxt = pending_ctxt, None
            if keyword == "msgctxt":
                pending_ctxt = value
                field = (keyword, None)
            elif keyword.startswith("msgstr"):
                current["msgstrs"].append(value)
                field = ("msgstrs", len(current["msgstrs"]) - 1)
            else:
                current[keyword] = value
                field = (keyword, None)
        elif line.startswith('"') and field:
            name, index = field
            chunk = po_unescape(line[1:-1])
            if name == "msgctxt":
                # Still buffered -- its entry has not started yet.
                pending_ctxt = (pending_ctxt or "") + chunk
            elif index is None:
                current[name] = (current[name] or "") + chunk
            else:
                current[name][index] += chunk

    if current["msgid"]:
        entries.append(current)
    return entries


def po_key(entry):
    """The ``extract()`` key an entry corresponds to."""
    return (entry["msgctxt"], entry["msgid"], entry["msgid_plural"])


def locale_files():
    """Every committed catalog: ``{language code: Path}``."""
    if not LOCALE_DIR.is_dir():
        return {}
    return {
        po.parent.parent.name: po
        for po in sorted(LOCALE_DIR.glob("*/LC_MESSAGES/django.po"))
    }


def format_entry(entry, refs=()):
    """One PO entry as text, with ``refs`` as its ``#:`` source references.

    Deliberately does not wrap long lines. gettext's own tools wrap at 77
    columns, but wrapping is cosmetic and unwrapped is both valid and far
    easier to diff -- a reworded sentence shows up as one changed line
    rather than a reflowed paragraph.
    """
    lines = [f"#: {ref}" for ref in refs]
    if entry["flags"]:
        lines.append(f"#, {', '.join(sorted(entry['flags']))}")
    if entry["msgctxt"] is not None:
        lines.append(f'msgctxt "{po_escape(entry["msgctxt"])}"')
    lines.append(f'msgid "{po_escape(entry["msgid"])}"')
    if entry["msgid_plural"] is None:
        lines.append(f'msgstr "{po_escape(entry["msgstrs"][0])}"')
    else:
        lines.append(f'msgid_plural "{po_escape(entry["msgid_plural"])}"')
        for index, msgstr in enumerate(entry["msgstrs"]):
            lines.append(f'msgstr[{index}] "{po_escape(msgstr)}"')
    return "\n".join(lines)


def write_po(path, comment, header, entries, references):
    """Rewrite a .po/.pot from parsed entries, refreshing source references.

    Translations are carried over verbatim from ``entries`` (normally
    parse_po() of the same file), so this is a *reference* refresh, not a
    regeneration: it is the one part of a catalog derived from the code
    rather than from a translator, and the only part that goes stale on its
    own every time a template gains a line.

    ``references`` is extract()'s mapping, so an entry no longer present in
    the source simply loses its references rather than silently keeping
    wrong ones.
    """
    blocks = [comment.rstrip("\n"), 'msgid ""\nmsgstr ""\n' + "\n".join(
        f'"{po_escape(line)}\\n"' for line in header.rstrip("\n").split("\n"))]
    for entry in entries:
        blocks.append(format_entry(entry, references.get(
            po_key(entry), [])))
    path.write_text("\n\n".join(blocks) + "\n", encoding="utf-8")


def po_comment(path):
    """The leading comment block, above the header entry."""
    lines = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.startswith("#"):
            break
        lines.append(raw)
    return "\n".join(lines)


def po_header(path):
    """The catalog header -- the msgstr belonging to the empty msgid.

    parse_po() drops it, since it is metadata rather than an entry, but a
    compiled catalog cannot do without it: ``gettext`` reads the charset to
    decode with and the Plural-Forms expression to select a plural form from
    exactly here. A .mo with no header entry decodes as ASCII and counts
    plurals the Germanic way regardless of language.
    """
    collecting, chunks = False, []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not collecting:
            # The header is the first entry in the file, so the first
            # `msgstr ""` encountered is necessarily its own.
            collecting = line == 'msgstr ""'
            continue
        if not line.startswith('"'):
            break
        chunks.append(po_unescape(line[1:-1]))
    return "".join(chunks)


# --- MO files ---------------------------------------------------------------
#
# `msgfmt` is a gettext binary, and this project cannot assume gettext is
# installed -- the same constraint that produced the extractor above. But
# unlike the .po files, a .mo is not optional decoration: Django's
# translation machinery reads *only* compiled catalogs, so an uncompiled
# language is an untranslated one no matter how complete its .po is.
#
# The format is small and fully specified (GNU gettext manual, "The Format of
# GNU MO Files"), so it is written out here directly. Tests do not trust this
# implementation to check itself: they read the shipped .mo back with the
# standard library's own gettext.GNUTranslations, which is an independent
# reader, and then assert Django actually serves the translations.

MO_MAGIC = 0x950412DE

#: gettext's separators, which are part of the lookup key rather than
#: decoration: a context is joined to its msgid with EOT, and the two halves
#: of a plural pair (and the plural forms of its translation) with NUL.
CONTEXT_GLUE = "\x04"
PLURAL_GLUE = "\x00"


def mo_key(entry):
    """The exact byte string gettext will look this entry up by."""
    msgid = entry["msgid"]
    if entry["msgctxt"] is not None:
        msgid = entry["msgctxt"] + CONTEXT_GLUE + msgid
    if entry["msgid_plural"] is not None:
        msgid = msgid + PLURAL_GLUE + entry["msgid_plural"]
    return msgid.encode("utf-8")


def mo_value(entry):
    """The translation blob: NUL-joined, one part per plural form."""
    return PLURAL_GLUE.join(entry["msgstrs"]).encode("utf-8")


def compile_mo(path):
    """Compile one .po file into GNU MO bytes.

    Untranslated and fuzzy entries are omitted rather than written empty,
    which is what `msgfmt` does and is load-bearing: an entry present with an
    empty translation makes gettext return the empty string, so the UI would
    render blank instead of falling back to the English source.
    """
    items = [(b"", po_header(path).encode("utf-8"))]
    for entry in parse_po(path):
        if "fuzzy" in entry["flags"] or not any(entry["msgstrs"]):
            continue
        items.append((mo_key(entry), mo_value(entry)))
    # Sorted by key because readers are entitled to binary-search the tables
    # (the C library does; Python's reads them linearly into a dict). Also
    # makes the output byte-for-byte reproducible from the same input.
    items.sort(key=lambda item: item[0])

    count = len(items)
    keys_start = 7 * 4 + 16 * count
    keys, values, key_index, value_index = b"", b"", [], []
    for key, _value in items:
        key_index.append((len(key), keys_start + len(keys)))
        keys += key + b"\x00"          # NUL-terminated for C readers; the
    values_start = keys_start + len(keys)   # length prefix is what Python uses
    for _key, value in items:
        value_index.append((len(value), values_start + len(values)))
        values += value + b"\x00"

    out = struct.pack(
        "<7I", MO_MAGIC, 0, count, 7 * 4, 7 * 4 + count * 8, 0, 0)
    for length, offset in key_index + value_index:
        out += struct.pack("<2I", length, offset)
    return out + keys + values


def mo_path(po):
    """Where a given .po's compiled form belongs."""
    return po.with_name("django.mo")
