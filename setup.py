import os
from setuptools import setup

with open(os.path.join(os.path.dirname(__file__), "README.rst")) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))
PROJECT_NAME = "django-mfa"

data_files = []
for dirpath, dirnames, filenames in os.walk(PROJECT_NAME):
    for i, dirname in enumerate(dirnames):
        if dirname.startswith("."):
            del dirnames[i]
    if "__init__.py" in filenames:
        continue
    elif filenames:
        for f in filenames:
            data_files.append(os.path.join(
                dirpath[len(PROJECT_NAME) + 1:], f))

install_requires = [
    "Django>=4.2",
    "fido2>=1.1.2,<3",
    "qrcode>=7.0.0,<9",
]

setup(
    name="django-mfa",
    version="4.0.0a1",
    packages=["django_mfa", "django_mfa.templatetags", "django_mfa.migrations"],
    include_package_data=True,
    description="A Django deployment package for all hosting types.",
    long_description=README,
    url="https://github.com/MicroPyramid/django-mfa",
    author="Micropyramid",
    author_email="hello@micropyramid.com",
    python_requires=">=3.10",
    classifiers=[
        "Environment :: Web Environment",
        "Framework :: Django",
        "Framework :: Django :: 4.2",
        "Framework :: Django :: 5.2",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
    ],
    install_requires=install_requires,
)
