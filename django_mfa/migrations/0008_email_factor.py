# Adds the "email" factor type.
#
# Two operations, and the second is the one that is easy to miss: the
# singleton constraint's condition is a literal list of type strings, so a new
# singleton factor that isn't added to it is simply not constrained. The
# adapter's supports_multiple = False would then be a promise nothing keeps,
# and a second row would race EmailAdapter.get_instances(user).first() --
# making which address receives the code depend on row order.
#
# Reversible, unlike 0007: nothing here destroys data. Reversing restores the
# previous choices and constraint; any "email" rows already created would then
# violate nothing (the constraint simply stops covering them) but would be
# unreadable by an adapter that no longer exists.
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("django_mfa", "0007_drop_legacy_models"),
    ]

    operations = [
        migrations.AlterField(
            model_name="authenticator",
            name="type",
            field=models.CharField(
                choices=[
                    ("totp", "Authenticator app"),
                    ("webauthn", "Security key or passkey"),
                    ("recovery_codes", "Recovery codes"),
                    ("email", "Emailed code"),
                ],
                max_length=32,
            ),
        ),
        migrations.RemoveConstraint(
            model_name="authenticator",
            name="mfa_one_singleton_authenticator_per_user",
        ),
        migrations.AddConstraint(
            model_name="authenticator",
            constraint=models.UniqueConstraint(
                condition=models.Q(
                    ("type__in", ["totp", "recovery_codes", "email"])),
                fields=("user", "type"),
                name="mfa_one_singleton_authenticator_per_user",
            ),
        ),
    ]
