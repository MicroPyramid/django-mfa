import os
from setuptools import setup

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))
PROJECT_NAME = 'django-mfa'

data_files = []
for dirpath, dirnames, filenames in os.walk(PROJECT_NAME):
    for i, dirname in enumerate(dirnames):
        if dirname.startswith('.'):
            del dirnames[i]
    if '__init__.py' in filenames:
        continue
    elif filenames:
        for f in filenames:
            data_files.append(os.path.join(
                dirpath[len(PROJECT_NAME) + 1:], f))

install_requires = [
    'asn1crypto==0.24.0',
    'cffi==1.12.2',
    'cryptography==2.6.1',
    'dj-database-url==0.4.1',
    'Django==2.1.5',
    'django-argonauts==1.2.0',
    'django-debug-toolbar==1.11',
    'gunicorn==19.6.0',
    'psycopg2==2.7',
    'pycparser==2.19',
    'python-u2flib-server==5.0.0',
    'pytz==2018.9',
    'qrcode==6.1',
    'six==1.12.0',
    'sqlparse==0.3.0',
    'whitenoise==3.1',
]

setup(
    name='django-mfa',
    version='1.2',
    packages=['django_mfa', 'django_mfa.templatetags', 'django_mfa.migrations'],
    include_package_data=True,
    description='A Django deployment package for all hosting types.',
    long_description=README,
    url='https://github.com/MicroPyramid/django-mfa',
    author='Micropyramid',
    author_email='hello@micropyramid.com',
    install_requires=install_requires,
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Framework :: Django',
        'Framework :: Django :: 1.11',
        'Framework :: Django :: 2.0',
        'Framework :: Django :: 2.1',
    ],
)
