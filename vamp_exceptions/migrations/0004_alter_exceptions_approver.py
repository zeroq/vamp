# Generated by Django 4.1.4 on 2023-03-11 16:00

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('vamp_exceptions', '0003_exceptions_host_alter_exceptions_finding'),
    ]

    operations = [
        migrations.AlterField(
            model_name='exceptions',
            name='approver',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='approver', to=settings.AUTH_USER_MODEL),
        ),
    ]