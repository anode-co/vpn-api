# Generated by Django 2.1.7 on 2020-04-29 12:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vpn', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vpnclientevent',
            name='ip4_address',
            field=models.CharField(blank=True, max_length=15, null=True),
        ),
        migrations.AlterField(
            model_name='vpnclientevent',
            name='ip6_address',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
    ]
