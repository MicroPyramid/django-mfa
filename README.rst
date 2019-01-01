django-mfa
==========

.. image:: https://readthedocs.org/projects/django-mfa/badge/?version=latest
   :target: http://django-mfa.readthedocs.io/en/latest/
   :alt: Documentation Status
   
.. image:: https://travis-ci.org/MicroPyramid/django-mfa.svg?branch=master
   :target: https://travis-ci.org/MicroPyramid/django-mfa

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

Django-mfa(Multi-factor Authentication) is a simple django package to add extra layer of security to your web application. Django-mfa is providing easiest integration to enable Multi factor authentication to your django applications. Inspired by the user experience of Google's Authentication, django-mfa allows users to authenticate through text message(SMS) or by using token generator app like google authenticator. 

We welcome your feedback on this package. If you run into problems, please raise an issue or contribute to the project by forking the repository and sending some pull requests. 

This Package is compatible with Django versions >=1.10 (including at least Django 2.0.7) Documentation is available at readthedocs(http://django-mfa.readthedocs.io/en/latest/)

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

1. Add app name in settings.py::

    INSTALLED_APPS = [
       '..................',
       'django_mfa',
       '..................'
    ]

2. Add 'django_mfa.middleware.MfaMiddleware' to your project middlewares::

    MIDDLEWARE = [
       '....................................',
       'django_mfa.middleware.MfaMiddleware',
       '....................................',
    ]

3. Optional issuer name.  This name will be shown in the Authenticator App along with the username

   MFA_ISSUER_NAME = "Cool Django App"

4. Optionally enable remember-my-browser.  If enabled, the browser will be trusted for specified number of days after the user enters the code once::

    MFA_REMEMBER_MY_BROWSER = True
    MFA_REMEMBER_DAYS = 90

Urls
~~~~

Add the following to your root urls.py file.

.. code:: django

    urlpatterns = [
        ...

        url(r'^settings/', include('django_mfa.urls')),
    ]


Done. With these settings you have now, you will get the MFA features.

You can try it by hosting on your own or deploy to Heroku with a button click.

.. image:: https://www.herokucdn.com/deploy/button.svg
   :target: https://heroku.com/deploy?template=https://github.com/MicroPyramid/django-mfa.git

Visit our Django web development page `Here`_

We welcome your feedback and support, raise `github ticket`_ if you want to report a bug. Need new features? `Contact us here`_

.. _contact us here: https://micropyramid.com/contact-us/
.. _Here: https://micropyramid.com/django-development-services/
.. _github ticket: https://github.com/MicroPyramid/django-mfa/issues

