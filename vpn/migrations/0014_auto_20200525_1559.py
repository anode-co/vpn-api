# Generated by Django 2.1.7 on 2020-05-25 15:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vpn', '0013_auto_20200525_1544'),
    ]

    operations = [
        migrations.AlterField(
            model_name='clientsoftwareversion',
            name='client_cpu_architecture',
            field=models.CharField(blank=True, choices=[('all', 'all'), ('i686', 'i686'), ('aarch64', 'aarch64'), ('armv7a', 'armv7a'), ('X86_64', 'X86_64')], max_length=20),
        ),
    ]
