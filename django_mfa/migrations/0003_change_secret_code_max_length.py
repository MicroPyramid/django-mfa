from __future__ import unicode_literals

from django.db import migrations
from django.db import models


class Migration(migrations.Migration):

    dependencies = [
        ('django_mfa', '0002_auto_20160706_1421'),
    ]

    operations = [
        migrations.AlterField(
            model_name='UserRecoveryCodes',
            name='secret_code',
            field=models.CharField(max_length=16),
        ),
    ]
