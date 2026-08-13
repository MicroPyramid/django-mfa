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
