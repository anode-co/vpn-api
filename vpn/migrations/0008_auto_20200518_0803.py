# Generated by Django 2.1.7 on 2020-05-18 08:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vpn', '0007_auto_20200515_1047'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vpnclientevent',
            name='available_memory_bytes',
            field=models.CharField(blank=True, max_length=32, null=True),
        ),
        migrations.AlterField(
            model_name='vpnclientevent',
            name='cpu_utilization_percent',
            field=models.CharField(blank=True, max_length=32, null=True),
        ),
    ]
