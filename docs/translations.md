# Translations

Every string django-mfa shows a user is translatable, and **six languages are
live**: a user whose browser asks for one of them gets django-mfa's screens in
it, with no configuration beyond switching Django's own i18n on.

## What ships

    django_mfa/locale/django.pot                     the template
    django_mfa/locale/<lang>/LC_MESSAGES/django.po   the source catalog
    django_mfa/locale/<lang>/LC_MESSAGES/django.mo   the compiled catalog

`de`, `es`, `fr`, `pt_BR`, `ja`, `zh_Hans` — complete, with no entry left
untranslated or `fuzzy`.

:::{note}
These catalogs were **machine-drafted and maintainer-reviewed, not reviewed by
a native speaker.** They are live because a good translation that reaches
users beats a perfect one that never ships — but if something reads wrong to
you, that is a bug worth reporting, and a one-line pull request against a
`.po` file is a genuinely welcome contribution.
:::

The `.mo` files are the half that matters at runtime: **Django reads only
compiled catalogs.** A `.po` is the source a translator edits; nothing serves
it directly.

## Using them in your project

Django's i18n has to be switched on in the host project — django-mfa can't do
it for you:

    USE_I18N = True

    MIDDLEWARE = [
        ...,
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.middleware.locale.LocaleMiddleware",     # after sessions
        "django.middleware.common.CommonMiddleware",
    ]

`LocaleMiddleware` is what picks a language per request. Without it every
request uses `LANGUAGE_CODE` and per-user language selection does nothing.

:::{warning}
Shadowing a template drops its translations with it. A copy of
`django_mfa/templates/django_mfa/verify_totp.html` in your own app replaces
the shipped file *and* its `{% trans %}` tags — the strings in your copy are
yours to translate, in your project's own catalog. See {doc}`customizing`.
:::

## Working on the catalogs

One command does everything mechanical:

    uv run python tools/compile_catalogs.py

It refreshes the `#:` source references in every catalog and recompiles every
`.mo`. It never invents, reorders or drops a translation — editing those is
the human part. `test_i18n.py` fails if a `.mo` is out of date with its `.po`,
so a forgotten run is caught in CI rather than shipped as a translation
nobody receives.

This is `makemessages` + `msgfmt` reimplemented in Python
(`django_mfa/tests/support/i18n.py`) because gettext's binaries are a system
package this project declines to require — including of its own CI.

### Fixing a translation

Edit the `msgstr` in `django_mfa/locale/<lang>/LC_MESSAGES/django.po`, run the
command above, and commit the `.po` and `.mo` together.

Placeholders like `%(name)s` must appear in the translation exactly as in the
source. Get one wrong and interpolation raises `KeyError` in the middle of
somebody's sign-in — this is the one translation mistake that is an outage
rather than an embarrassment. A test enforces it; understanding why matters
more than the test does.

### Adding a language

Copy `django.pot` to `django_mfa/locale/<lang>/LC_MESSAGES/django.po`, set
`Language:` and `Plural-Forms:` in its header, translate every `msgstr`, and
run the command above.

Getting `Plural-Forms` right matters more than it looks: it is what selects
between `msgstr[0]` and `msgstr[1]`, so a wrong rule produces fluent text
attached to the wrong number. The
[gettext manual's table](https://www.gnu.org/software/gettext/manual/html_node/Plural-forms.html)
has the correct expression for each language.

A partial catalog is not useful here — a page rendered half in the user's
language and half in English is worse than one rendered wholly in English —
and `test_i18n.py` requires every entry to be translated.

### Adding or changing a string

Wrap it: `{% trans %}` / `{% blocktrans %}` in a template, `gettext_lazy as _`
in Python. Then add the entry by hand to `django.pot` and to each `.po`, and
run the command above. `test_i18n.py` fails while the catalogs and the code
disagree, so this cannot be half-done quietly.

:::{warning}
**Give a generic string a `context`.** gettext keys on the string itself, and
Django merges every installed app's catalog into one per language — so a bare
`{% trans "Save" %}` collides with `django.contrib.admin`'s own `"Save"`, and
whichever app `INSTALLED_APPS` lists *first* wins the key. Admin is listed
first in nearly every project.

The result is invisible: the page renders, in the right language, in another
app's words — and only in the languages that app translates, so reading the
English UI will never reveal it. `"Remove"` was exactly this, silently served
as admin's wording, until it became:

    {% trans "Remove" context "second-factor method" %}

`test_i18n.py` now fails on any bare msgid that a bundled Django app also
translates. The fix is always a context, never rewording around admin.
:::

Two things are deliberately **not** translated: management-command output and
system-check messages. Both are read by operators and developers, not end
users, and both are matched against by scripts.
