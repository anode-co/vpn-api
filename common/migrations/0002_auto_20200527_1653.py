# Generated by Django 2.1.7 on 2020-05-27 16:53

import common.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('common', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelManagers(
            name='user',
            managers=[
                ('objects', common.models.UserManager()),
            ],
        ),
        migrations.AddField(
            model_name='user',
            name='private_key',
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='public_key',
            field=models.CharField(blank=True, max_length=150, null=True),
        ),
    ]
