# Generated by Django 4.1.4 on 2023-10-29 13:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vamp_api', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='tenableapi',
            name='severities',
            field=models.CharField(blank=True, default='', max_length=1024),
        ),
    ]
