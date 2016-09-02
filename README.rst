django-mfa
==========

.. image:: https://readthedocs.org/projects/django-mfa/badge/?version=latest
   :target: http://django-mfa.readthedocs.io/en/latest/
   :alt: Documentation Status
   
.. image:: https://travis-ci.org/MicroPyramid/django-mfa.svg?branch=master
   :target: https://travis-ci.org/MicroPyramid/django-mfa

.. image:: https://img.shields.io/pypi/dm/django-mfa.svg
    :target: https://pypi.python.org/pypi/django-mfa
    :alt: Downloads

.. image:: https://img.shields.io/pypi/v/django-mfa.svg
    :target: https://pypi.python.org/pypi/django-mfa
    :alt: Latest Release
    
.. image:: https://coveralls.io/repos/github/MicroPyramid/django-mfa/badge.svg?branch=master
   :target: https://coveralls.io/github/MicroPyramid/django-mfa?branch=master

.. image:: https://landscape.io/github/MicroPyramid/django-mfa/master/landscape.svg?style=flat
   :target: https://landscape.io/github/MicroPyramid/django-mfa/master
   :alt: Code Health

.. image:: https://img.shields.io/github/license/micropyramid/django-mfa.svg
    :target: https://pypi.python.org/pypi/django-mfa/


Django-mfa is a simple Django app to for providing the MFA.

**Documentation** is `avaliable online
<http://django-simple-mfa.readthedocs.org/>`_, or in the docs
directory of the project.

Quick start
-----------

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

Add ``otp_app'`` to the ``INSTALLED_APPS`` to your *settings.py*.

See the :doc:`settings` section for other settings.

Add ``'otp_app.middleware.MfaMiddleware'`` to the ``MIDDLEWARE_CLASSES``

Urls
~~~~

Add the following to your root urls.py file.

.. code:: django

    urlpatterns = [
        ...

        url(r'^settings/', include('otp_app.urls', namespace="mfa")),
    ]


Done. With these settings you have now, you will get the MFA features.

.. _contact us here: https://micropyramid.com/contact-us/
