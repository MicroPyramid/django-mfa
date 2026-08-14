#!/usr/bin/env python
import os
import sys

import django
from django.conf import settings
from django.test.utils import get_runner

if __name__ == "__main__":
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    settings.configure(
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
            }
        },
        INSTALLED_APPS=(
            'django.contrib.admin',
            'django.contrib.auth',
            'django.contrib.contenttypes',
            'django.contrib.sessions',
            'django.contrib.messages',
            'django.contrib.staticfiles',
            'django_mfa',
            # Test-only: the importer commands (tasks 11-12) read these
            # packages' models. Real models rather than stubs, so a field
            # rename upstream fails the test instead of silently
            # invalidating the importer. They are never runtime
            # dependencies of django_mfa -- see mfa_import_django_otp.py
            # and mfa_import_django_mfa2.py, which resolve them through
            # apps.get_model() and degrade to a clean CommandError.
            'django_otp',
            'django_otp.plugins.otp_totp',
            'django_otp.plugins.otp_static',
            'django_otp.plugins.otp_email',
            'mfa',
        ),
        MIDDLEWARE=(
            'django.middleware.security.SecurityMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.middleware.common.CommonMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'django.contrib.messages.middleware.MessageMiddleware',
            'django.middleware.clickjacking.XFrameOptionsMiddleware',
            'django_mfa.middleware.MfaMiddleware',
        ),
        ROOT_URLCONF='django_mfa.urls',
        STATIC_URL='/static/',
        TEMPLATES=[
            {
                'BACKEND': 'django.template.backends.django.DjangoTemplates',
                'DIRS': [os.path.join(BASE_DIR, 'django_mfa/templates')],
                'APP_DIRS': True,
                'OPTIONS': {
                    'context_processors': [
                        'django.template.context_processors.debug',
                        'django.template.context_processors.request',
                        'django.contrib.auth.context_processors.auth',
                        'django.contrib.messages.context_processors.messages',
                    ],
                },
            },
        ],
        SECRET_KEY='test_secret_key',
        # django-mfa2's own AppConfig ('mfa', pulled in for the importer
        # tests -- see INSTALLED_APPS above) omits default_auto_field, which
        # otherwise trips models.W042 on its User_Keys model. django_mfa's
        # own AppConfig already sets default_auto_field explicitly
        # (django_mfa/apps.py), so this global only affects apps that don't
        # set their own -- it does not change django_mfa's behaviour. Django
        # migrations hard-code their field types per file, so this also
        # cannot alter any already-applied migration; it only affects a
        # future makemigrations, which this project never runs against 'mfa'.
        DEFAULT_AUTO_FIELD='django.db.models.BigAutoField',
        MFA_FIDO2_RP_ID='testserver',
        ALLOWED_HOSTS=['testserver', 'localhost'],
        # django_mfa.checks.E003 (task 19) flags a WebAuthn-capable install
        # that is missing this backend -- without it, passkey login "works"
        # once and then silently degrades to an anonymous session on the
        # very next request (see checks.py). The registry always registers
        # a WebAuthn adapter by default, so these settings need it too, the
        # same way MFA_FIDO2_RP_ID/ALLOWED_HOSTS above exist to keep E001/
        # E002 clean.
        AUTHENTICATION_BACKENDS=[
            'django_mfa.backends.WebAuthnBackend',
            'django.contrib.auth.backends.ModelBackend',
        ],
        CACHES={"default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
        # Pinned explicitly rather than left to Django's own default:
        # that default is USE_TZ=False on Django 4.2 (this project's floor,
        # and a leg of the CI matrix) but USE_TZ=True on Django 5.2 (another
        # leg), so an unpinned suite exercises naive/aware datetime handling
        # differently per Django version and a regression on one leg can go
        # uncaught on the other. Three separate naive/aware bugs surfaced
        # during the branch that added MfaExemption and its --until date
        # handling, and the suite as it stood didn't catch any of them.
        # Pinning True here doesn't remove USE_TZ=False coverage: the tests
        # that specifically need it (e.g. MfaExemptionStrTests,
        # MfaDisableUntilUseTzTests) wrap themselves in their own
        # override_settings(USE_TZ=False) -- that's the deliberate other
        # half of this pin, not a gap in it.
        USE_TZ=True,
    )

    django.setup()
    TestRunner = get_runner(settings)
    test_runner = TestRunner()
    # Accepts an optional test label on argv, e.g.
    # `python test_runner.py django_mfa.tests.test_conf`, to narrow a run
    # without editing this file (see CLAUDE.md).
    labels = sys.argv[1:] or ["django_mfa"]
    failures = test_runner.run_tests(labels)
    sys.exit(bool(failures))
