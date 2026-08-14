# Translations

Every string django-mfa shows a user is translatable. What ships today is the
machinery plus six machine-drafted catalogs; **no translation is live yet**,
by design. This page covers what you get out of the box, what your project
has to do to use it, and how to review a language so it starts appearing.

## What ships

    django_mfa/locale/django.pot            the template, 75 entries
    django_mfa/locale/<lang>/LC_MESSAGES/django.po

Six languages have draft catalogs: `de`, `es`, `fr`, `pt_BR`, `ja`, `zh_Hans`.

Every entry in every one of them is marked `#, fuzzy`. That is not an
oversight — it is the whole safety model. gettext skips a fuzzy entry and
falls back to the English source, so a machine draft nobody has read cannot
put words in your product's mouth on a sign-in screen. `django_mfa/tests/`
`test_i18n.py` fails the build if a fuzzy flag disappears without the
deliberate steps below.

For the same reason **no compiled `.mo` files ship**: a fully fuzzy catalog
compiles to an empty one, so shipping it would add bytes and change nothing.

## Using them in your project

Django's i18n has to be switched on in the host project — django-mfa can't
do it for you:

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

## Reviewing a language so it goes live

A draft becomes a real translation when a human who reads the language has
checked it. The steps, in order:

1. Read `django_mfa/locale/<lang>/LC_MESSAGES/django.po` end to end. Fix
   what's wrong. Pay particular attention to `%(name)s` placeholders: they
   must appear in the translation exactly as in the source, or interpolation
   raises `KeyError` in the middle of somebody's sign-in. A test enforces
   this, but understanding why matters more than the test.
2. Remove the `#, fuzzy` line above each entry you have reviewed. An entry
   keeps falling back to English until you do.
3. Compile it: `django-admin compilemessages -l <lang>`. This needs the
   `gettext` tools installed (`apt install gettext`, `brew install gettext`).
4. Commit the `.mo` alongside the `.po`. It is deliberately un-ignored in
   `.gitignore` — the `.mo` is the file gettext reads at runtime, and
   hatchling won't put an ignored file in the wheel.
5. Update `test_i18n.py`'s `DraftsStayInertTests`, which asserts nothing is
   live. Make it assert what's now true — that this language is reviewed and
   the others are not. Changing that test should feel deliberate.

## Adding a language

    django-admin makemessages -l <lang>       # run from django_mfa/

Then follow the review steps above. There is no draft to start from, which
is fine: an empty `msgstr` falls back to English exactly as a fuzzy one does.

## Adding or changing a string

Wrap it — `{% trans %}` / `{% blocktrans %}` in a template,
`gettext_lazy as _` in Python — then regenerate:

    django-admin makemessages -a --keep-pot   # from django_mfa/

`test_i18n.py` fails if the catalog and the code disagree, so a forgotten
regeneration is caught in CI rather than discovered by a translator months
later. That check runs a pure-Python extractor (`tests/support/i18n.py`)
rather than shelling out to `xgettext`, so it works on machines and CI
images that have no gettext installed.

Two things are deliberately **not** translated: management-command output
and system-check messages. Both are read by operators and developers, not
end users, and both are matched against by scripts.
