# Generated by Django 4.1.4 on 2023-03-11 14:51

from django.conf import settings
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('vamp_scans', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('vamp_exceptions', '0001_initial'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='Exception',
            new_name='Exceptions',
        ),
    ]