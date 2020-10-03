# Generated by Django 2.2.13 on 2020-10-03 09:14

from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('vpn', '0019_auto_20200714_1330'),
    ]

    operations = [
        migrations.AddField(
            model_name='cjdnsvpnserver',
            name='average_rating',
            field=models.DecimalField(blank=True, decimal_places=1, max_digits=2, null=True),
        ),
        migrations.AddField(
            model_name='cjdnsvpnserver',
            name='num_ratings',
            field=models.BigIntegerField(default=0, validators=[django.core.validators.MinValueValidator(0)]),
        ),
        migrations.AlterField(
            model_name='vpnclientevent',
            name='error',
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.CreateModel(
            name='UserCjdnsVpnServerRating',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('rating', models.SmallIntegerField(validators=[django.core.validators.MinValueValidator(0), django.core.validators.MaxValueValidator(5)])),
                ('created_at', models.DateTimeField(auto_now=True)),
                ('cjdns_vpn_server', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='vpn.CjdnsVpnServer')),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
