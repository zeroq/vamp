from django.db import models
from django.contrib.auth.models import User

from vamp_scans.models import Finding, Host

# Create your models here.

class Exceptions(models.Model):
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, blank=True, null=True)
    host = models.ForeignKey(Host, on_delete=models.CASCADE, blank=True, null=True)
    requestor = models.ForeignKey(User, on_delete=models.CASCADE, related_name='requestor')
    approver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='approver', blank=True, null=True)
    reason = models.CharField(max_length=2048, blank=True)
    duration = models.IntegerField(default=90)  # days exception is valid
    created = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)
    approved = models.BooleanField(default=False)
    still_valid = models.BooleanField(default=False)

class Ignore(models.Model):
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, blank=True, null=True)
    host = models.ForeignKey(Host, on_delete=models.CASCADE, blank=True, null=True)
    requestor = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ignore_requestor')
    approver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ignore_approver', blank=True, null=True)
    reason = models.CharField(max_length=2048, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)
    approved = models.BooleanField(default=False)
