from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("django-mfa")
except PackageNotFoundError:  # running from a source checkout, not installed
    __version__ = "0.0.0.dev0"

# NOTE: `default_app_config` used to live here. Django deprecated it in 3.2 and
# REMOVED it in 4.1 -- on this project's floor (4.2) it was dead code that
# Django never read. DjangoMfaAppConfig is discovered automatically because it
# is the only AppConfig in django_mfa/apps.py.
