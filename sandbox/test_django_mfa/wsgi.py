"""
WSGI config for test_django_mfa project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/1.11/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "test_django_mfa.settings")

# 'whitenoise.django.DjangoWhiteNoise' (whitenoise 3.x) no longer exists in
# any current whitenoise release -- modern whitenoise integrates as
# 'whitenoise.middleware.WhiteNoiseMiddleware' in MIDDLEWARE instead of
# wrapping the WSGI application by hand. See the STORAGES comment in
# settings.py for why it isn't wired back in here.
application = get_wsgi_application()
