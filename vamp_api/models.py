from django.db import models

# Create your models here.

class TenableAPI(models.Model):
    server = models.CharField(max_length=1024)
    access_key = models.CharField(max_length=200)
    secret_key = models.CharField(max_length=200)
    severities = models.CharField(max_length=1024, default='')  # comma separated list of severities to fetch
