# Generated by Django 2.1.7 on 2020-05-25 15:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vpn', '0011_auto_20200522_1414'),
    ]

    operations = [
        migrations.AddField(
            model_name='cjdnsvpnserver',
            name='is_fake',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='vpnclientevent',
            name='error',
            field=models.CharField(choices=[('connectionFailed', 'Could not connect'), ('disconnection', 'Unexpected disconnection'), ('route_stopped', 'Connected but unable to route traffic'), ('cjdns_crash', 'CJDNS crashed'), ('connection', 'VPN client connected'), ('disconnection', 'VPN client disconnected'), ('cjdroute', 'Cjdroute problem'), ('cjdns_socket', 'Cjdns socket error'), ('vpn_service', 'VPN service problem'), ('other', 'Other reason')], max_length=64),
        ),
    ]
