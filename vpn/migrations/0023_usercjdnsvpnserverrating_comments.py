# Generated by Django 2.2.13 on 2020-12-11 20:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vpn', '0022_auto_20201009_1957'),
    ]

    operations = [
        migrations.AddField(
            model_name='usercjdnsvpnserverrating',
            name='comments',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
    ]
