from django.db import migrations

from django_mfa.migrations import _helpers


def forwards(apps, schema_editor):
    _helpers.forward(
        apps.get_model("django_mfa", "Authenticator"),
        apps.get_model("django_mfa", "UserOTP"),
        apps.get_model("django_mfa", "UserRecoveryCodes"),
    )


def backwards(apps, schema_editor):
    _helpers.reverse(apps.get_model("django_mfa", "Authenticator"))


class Migration(migrations.Migration):
    dependencies = [("django_mfa", "0004_authenticator")]
    operations = [migrations.RunPython(forwards, backwards)]
