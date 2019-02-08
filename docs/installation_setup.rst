Getting started
===============

Requirements
~~~~~~~~~~~~

======  ====================
Python  >= 2.6 (or Python 3)
Django  < 1.10
======  ====================

Installation
~~~~~~~~~~~~

The Git repository can be cloned with this command::

    git clone https://github.com/MicroPyramid/django-mfa

The ``django_mfa`` package, included in the distribution, should be
placed on the ``PYTHONPATH``.

Otherwise you can just ``easy_install -Z django-mfa``
or ``pip install django-mfa``.

Settings
~~~~~~~~

Add ``django_mfa'`` to the ``INSTALLED_APPS`` to your *settings.py*.

See the :doc:`settings` section for other settings.

Add ``'django_mfa.middleware.MfaMiddleware'`` to the ``MIDDLEWARE_CLASSES``

Urls
~~~~

Add the following to your root urls.py file.

.. code:: django

    urlpatterns = [
        ...

        url(r'^settings/', include('django_mfa.urls', namespace="mfa")),
    ]


Done. With these settings you have now, you will get the MFA features.
