# Generated by Django 2.2.13 on 2020-10-09 19:41

from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('vpn', '0020_auto_20201003_0914'),
    ]

    operations = [
        migrations.AlterField(
            model_name='usercjdnsvpnserverrating',
            name='rating',
            field=models.DecimalField(decimal_places=1, max_digits=2, validators=[django.core.validators.MinValueValidator(0), django.core.validators.MaxValueValidator(5)]),
        ),
        migrations.CreateModel(
            name='UserCjdnsVpnServerFavorite',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now=True)),
                ('cjdns_vpn_server', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='vpn.CjdnsVpnServer')),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
