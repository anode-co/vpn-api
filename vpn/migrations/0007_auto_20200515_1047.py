# Generated by Django 2.1.7 on 2020-05-15 10:47

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('vpn', '0006_auto_20200515_1047'),
    ]

    operations = [
        migrations.RenameField(
            model_name='vpnclientevent',
            old_name='available_memory',
            new_name='available_memory_bytes',
        ),
        migrations.RenameField(
            model_name='vpnclientevent',
            old_name='cpu_utilization',
            new_name='cpu_utilization_percent',
        ),
    ]
