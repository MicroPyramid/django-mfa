Getting started
===============

Requirements
~~~~~~~~~~~~

======  ====================
Python  3.6, 3.7, 3.8, 3.9, 3.10
Django  2.2, 3.0, 3.1, 3.2
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
