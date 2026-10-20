# Translations

django-mfa's screens, emails and JSON API error messages ship in six languages
besides English. A user whose browser asks for one of them sees django-mfa in that
language once your project picks a language per request.

## Switching languages on

Add Django's `LocaleMiddleware`, after the session middleware and before the
common middleware:

```python
# settings.py
USE_I18N = True  # Django's default

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    # ...the rest, including django_mfa.middleware.MfaMiddleware
]
```

To check it worked, set your browser's preferred language to German and open the
security page (`mfa:security_settings`). The heading should read
"Zwei-Faktor-Authentifizierung".

Without `LocaleMiddleware` (or another way of activating a language), every
request uses `LANGUAGE_CODE`. That is enough for a site that runs in one language:
set `LANGUAGE_CODE = "de"` and the MFA pages are in German.

## Shipped languages

| Language | Code in `LANGUAGES` | Catalog directory |
|---|---|---|
| German | `de` | `de` |
| Spanish | `es` | `es` |
| French | `fr` | `fr` |
| Brazilian Portuguese | `pt-br` | `pt_BR` |
| Japanese | `ja` | `ja` |
| Simplified Chinese | `zh-hans` | `zh_Hans` |

Django's default `LANGUAGES` includes all six. If you set your own `LANGUAGES`,
a language you leave out is never selected.

Every string is translated in every catalog. The translations were drafted by
machine and reviewed by the maintainers, not by native speakers. If something
reads wrong, please open an issue or send a pull request; see
[Contributing a language or a fix](#contributing-a-language-or-a-fix).

## Changing a wording

**For every language at once**, replace the template and write your own text; see
[Replace individual templates](customizing.md#replace-individual-templates).
Strings you leave unchanged inside `{% trans %}` keep django-mfa's translations.
Strings you change are yours to translate in your project's own catalog.

**For one language, without touching templates**, add the string to a catalog in
one of your `LOCALE_PATHS`. Django gives those catalogs priority over every
app's, so your translation wins. This works for English too:

```text
# mfa_locale/en/LC_MESSAGES/django.po
msgid ""
msgstr ""
"Content-Type: text/plain; charset=UTF-8\n"
"Language: en\n"
"Plural-Forms: nplurals=2; plural=(n != 1);\n"

msgid "Verify"
msgstr "Confirm"

msgctxt "second-factor method"
msgid "Remove"
msgstr "Delete"
```

```python
# settings.py
LOCALE_PATHS = [
    BASE_DIR / "locale",      # your own strings, managed by makemessages
    BASE_DIR / "mfa_locale",  # your django-mfa overrides
]
```

```bash
python manage.py compilemessages
```

`compilemessages` needs GNU gettext installed. Copy each `msgid`, and its
`msgctxt` if it has one, exactly from django-mfa's `django.pot`. An entry whose
text or context differs by a single character has no effect.

Keep these overrides in a directory of their own, as above. `makemessages` only
knows about strings in your own code, so in a catalog it manages it would mark
django-mfa's entries obsolete, and obsolete entries are not compiled.

## Adding a language

1. Copy django-mfa's `django.pot` to
   `mfa_locale/<directory>/LC_MESSAGES/django.po` in your project, where
   `<directory>` is the locale name (`it`, `nl`, `pl`). This prints where the
   installed package keeps it:

   ```bash
   python -c "import django_mfa, pathlib; print(pathlib.Path(django_mfa.__file__).parent / 'locale' / 'django.pot')"
   ```

2. In its header, set `Language:` and `Plural-Forms:`. The
   [gettext manual's table](https://www.gnu.org/software/gettext/manual/html_node/Plural-forms.html)
   has the right `Plural-Forms` line for each language. A wrong one attaches
   the right words to the wrong number.
3. Fill in every `msgstr`. An entry left empty shows in English.
4. Keep every placeholder, such as `%(code)s` or `%(remaining)s`, exactly as in
   the `msgid`. A renamed placeholder makes Django fall back to English for that
   string (or raise an error, for a string built in Python). A missing one drops
   the value without warning: a sign-in email without its code.
5. Add the directory to `LOCALE_PATHS` and run `python manage.py compilemessages`.

Then, please consider contributing it back.

## Contributing a language or a fix

From a checkout of the repository:

1. Edit or create `django_mfa/locale/<directory>/LC_MESSAGES/django.po`. For a
   new language, follow the steps above, starting from `django_mfa/locale/django.pot`.
2. Compile it. This does not need gettext:

   ```bash
   uv run python tools/compile_catalogs.py
   ```

3. Run the translation tests. They fail on an untranslated or `fuzzy` entry, a
   `.mo` that does not match its `.po`, or a placeholder that differs from the
   source string.

   ```bash
   uv run python test_runner.py django_mfa.tests.test_i18n
   ```

4. Send a pull request with the `.po` and the `.mo` together.

## For maintainers

### Regenerating catalogs

```bash
uv run python tools/compile_catalogs.py
```

This refreshes the `#:` source references in `django.pot` and every `.po`, and
recompiles every `.mo`. It never adds, removes or changes a translation. It is a
pure-Python stand-in for `makemessages` and `msgfmt`, so contributors and CI do
not need gettext.

### Why the `.mo` files are committed

Django reads only compiled `.mo` files, so a `.po` edited without recompiling
changes nothing a user sees. The build does not compile catalogs, and it leaves
out anything `.gitignore` ignores. That is why `.gitignore` un-ignores the `.pot`
and `.mo` files under `django_mfa/locale/`, and why each `.mo` is committed with
its `.po`. `test_i18n.py` fails when the two disagree, and `test_packaging.py`
fails when the wheel is missing a catalog.

### Adding or changing a string

1. Wrap it: `{% trans %}` or `{% blocktrans %}` in a template, `gettext_lazy` in
   Python.
2. Add the entry by hand to `django.pot` and to every `.po`, translated. The
   compile tool does not add entries, and the tests require every language to be
   complete.
3. Run `uv run python tools/compile_catalogs.py` and the tests.

### Give generic strings a `context`

Django merges every installed app's catalog into one per language, keyed on the
string itself. When two apps translate the same string, the app listed first in
`INSTALLED_APPS` wins, and that is usually `django.contrib.admin`. A bare
`{% trans "Remove" %}` was served with admin's wording in every language admin
translates, which nobody reading the English page would notice. A context makes
the key django-mfa's own:

```html+django
{% trans "Remove" context "second-factor method" %}
```

In Python, use `pgettext_lazy("second-factor method", "Remove")`.
`test_i18n.py` fails on any string without a context that a bundled Django app
also translates. Fix it with a context, not by rewording.

### What is not translated

Management command output and system check messages stay in English. Operators
and developers read them, and scripts match against them.
