# Generated by Django 4.1.4 on 2023-03-25 14:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vamp_exceptions', '0004_alter_exceptions_approver'),
    ]

    operations = [
        migrations.AddField(
            model_name='exceptions',
            name='approved',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='exceptions',
            name='still_valid',
            field=models.BooleanField(default=False),
        ),
    ]