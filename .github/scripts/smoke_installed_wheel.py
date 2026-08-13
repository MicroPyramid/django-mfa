"""Start Django against the INSTALLED django-mfa wheel, not the source tree.

Run this with the interpreter of a virtualenv that has the built wheel
installed, from a working directory that is not the checkout::

    uv venv /tmp/smoke
    VIRTUAL_ENV=/tmp/smoke uv pip install dist/*.whl
    cd /tmp && /tmp/smoke/bin/python \
        "$GITHUB_WORKSPACE/.github/scripts/smoke_installed_wheel.py"

Python puts *this file's* directory on sys.path, not the repo root, so a
module missing from the wheel cannot be masked by the checkout — which is the
whole point. The previous setup.py enumerated subpackages by hand, its list
predated django_mfa/adapters/ and django_mfa/views/, and the published wheel
shipped without either: `pip install django-mfa` raised ImportError from
DjangoMfaAppConfig.ready() while the entire test suite stayed green, because
tests run from a source checkout where those directories exist regardless.

Shared verbatim by the `package` job in ci.yml and the `build` job in
publish.yml. Both need exactly this check, and a copy in each file is a copy
that will drift.
"""

import django
from django.conf import settings

settings.configure(
    DEBUG=False,
    SECRET_KEY="x",
    ALLOWED_HOSTS=["example.com"],
    DATABASES={
        "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}
    },
    INSTALLED_APPS=[
        "django.contrib.auth",
        "django.contrib.contenttypes",
        "django.contrib.staticfiles",
        "django_mfa",
    ],
    MIDDLEWARE=[],
    MFA_FIDO2_RP_ID="example.com",
    USE_TZ=True,
    STATIC_URL="/static/",
    TEMPLATES=[
        {
            "BACKEND": "django.template.backends.django.DjangoTemplates",
            "APP_DIRS": True,
            "DIRS": [],
            "OPTIONS": {},
        }
    ],
    # Required, or django_mfa.E003 fails the check below -- which is the check
    # working as intended, not a packaging problem.
    AUTHENTICATION_BACKENDS=[
        "django_mfa.backends.WebAuthnBackend",
        "django.contrib.auth.backends.ModelBackend",
    ],
)
django.setup()

from django.core.management import call_command  # noqa: E402

call_command("check")
call_command("migrate", run_syncdb=True, verbosity=0)

# Templates and static files are the parts that ride on file inclusion rather
# than package discovery, so prove them explicitly.
from django.contrib.staticfiles import finders  # noqa: E402
from django.template.loader import get_template  # noqa: E402

get_template("django_mfa/security.html")
assert finders.find("django_mfa/webauthn.js"), "webauthn.js missing"
assert finders.find("django_mfa/style.css"), "style.css missing"

print("installed package starts, checks, migrates, renders, serves static")
