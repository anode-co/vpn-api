# Generated by Django 2.2 on 2020-06-12 17:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('common', '0017_auto_20200612_1657'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='username',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]
