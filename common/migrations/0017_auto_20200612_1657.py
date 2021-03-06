# Generated by Django 2.2 on 2020-06-12 16:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('common', '0016_user_is_app_secret_seen'),
    ]

    operations = [
        migrations.RenameField(
            model_name='user',
            old_name='app_secret_token',
            new_name='backup_wallet_password',
        ),
        migrations.RenameField(
            model_name='user',
            old_name='is_app_secret_seen',
            new_name='is_backup_wallet_password_seen',
        ),
        migrations.AddField(
            model_name='user',
            name='password_recovery_token',
            field=models.CharField(blank=True, max_length=65, null=True),
        ),
    ]
