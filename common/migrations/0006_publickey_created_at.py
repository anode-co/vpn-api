# Generated by Django 2.2 on 2020-05-28 18:50

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('common', '0005_publickey'),
    ]

    operations = [
        migrations.AddField(
            model_name='publickey',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
    ]
