# Generated by Django 2.2 on 2020-05-29 18:11

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('common', '0010_auto_20200529_1655'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='publickey',
            name='e',
        ),
        migrations.RemoveField(
            model_name='publickey',
            name='n',
        ),
    ]
