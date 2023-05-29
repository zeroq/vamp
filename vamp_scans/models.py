
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import User

# Create your models here.

class Host(models.Model):
    name = models.CharField(max_length=200)
    ip = models.GenericIPAddressField()
    fqdn = models.CharField(max_length=200, default="")
    netbios_name = models.CharField(max_length=200, default="")
    rdns = models.CharField(max_length=200, default="")
    predicted_os = models.CharField(max_length=200, blank=True, null=True)
    os = models.CharField(max_length=200, default="unknown")
    first_scan = models.DateTimeField(auto_now_add=True)
    last_scan = models.DateTimeField(auto_now=True)
    internet_facing = models.BooleanField(default=False)
    contacts = models.ManyToManyField('Contact', blank=True)
    tags = models.ManyToManyField('Tag', blank=True)
    groups = models.ManyToManyField('HostGroup', blank=True)

    def __str__(self):
        return "%s" % (self.ip)

    class Meta:
        unique_together = ('ip', 'fqdn', 'netbios_name', 'rdns',)

class HostComment(models.Model):
    host = models.ForeignKey('Host', on_delete=models.CASCADE)
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    creation_time = models.DateTimeField(auto_now_add=True)
    ctext = models.TextField()

class Contact(models.Model):
    class ContactTypChoices(models.TextChoices):
        RESPONSIBLE = 'RS', _('Responsible')
        ADMINISTRATOR = 'AD', _('Administrator')
        ESCALATION = 'ES', _('Escalation Contact')
    typ = models.CharField(max_length=2, choices=ContactTypChoices.choices, default=ContactTypChoices.RESPONSIBLE)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField()

    def __str__(self):
        return "%s %s (%s)" % (self.first_name, self.last_name, self.email)

    class Meta:
        unique_together = ('first_name', 'last_name', 'email',)

class Finding(models.Model):
    host = models.ForeignKey('Host', on_delete=models.CASCADE)
    uuid = models.CharField(max_length=36, unique=True)
    scan_date = models.DateTimeField()  # when did the scanner pick this up
    first_seen = models.DateTimeField(auto_now_add=True)  # vulnerability first seen in this platform
    last_seen = models.DateTimeField(auto_now=True)  # vulnerability last seen
    last_reported = models.DateTimeField(blank=True, null=True)  # last reported to escalation contact
    date_remediated = models.DateTimeField(blank=True, null=True)  # when was it set to different status than open
    escalated = models.BooleanField(default=False)
    name = models.CharField(max_length=200)
    source = models.CharField(max_length=200) # e.g. nessus, netsparker, burp, ...
    service = models.CharField(max_length=200, blank=True, null=True)
    cve = models.CharField(max_length=200, blank=True, null=True)
    link = models.CharField(max_length=200, blank=True, null=True)
    url = models.CharField(max_length=2048, blank=True, null=True)
    port = models.IntegerField(default=0)
    protocol = models.CharField(max_length=10, default='tcp')
    class SeverityChoices(models.IntegerChoices):
        INFO = 0, 'informative'
        LOW = 1, 'low',
        MEDIUM = 2, 'medium'
        HIGH = 3, 'high'
        CRITICAL = 4, 'critical'
    severity = models.IntegerField(choices=SeverityChoices.choices, default=SeverityChoices.INFO)
    class RemediationChoices(models.IntegerChoices):
        OPEN = 0, 'open'
        PATCHED = 1, 'patched'
        WORKAROUND = 2, 'workaround'
        EXCEPTION = 3, 'exception'
        FALSE = 4, 'false'
        IGNORE = 5, 'ignore'
        PROGRESS = 6, 'progress'
    status = models.IntegerField(choices=RemediationChoices.choices, default=RemediationChoices.OPEN)
    description = models.TextField(blank=True)
    short = models.CharField(max_length=2048, blank=True)
    exploit_available = models.BooleanField(default=False)
    exploited_in_the_wild = models.BooleanField(default=False)
    tags = models.ManyToManyField('Tag', blank=True)

    def __str__(self):
        return "%s - %s" % (self.name, self.short)

class Comment(models.Model):
    finding = models.ForeignKey('Finding', on_delete=models.CASCADE)
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    creation_time = models.DateTimeField(auto_now_add=True)
    ctext = models.TextField()

class Tag(models.Model):
    tag = models.CharField(max_length=256)
    creation_date = models.DateTimeField(auto_now_add=True)
    link = models.CharField(max_length=2048, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    class TagTypeChoices(models.IntegerChoices):
        AUTOMATIC = 0, 'automatic'
        MANUAL = 1, 'manual'
    ttype = models.IntegerField(choices=TagTypeChoices.choices, default=TagTypeChoices.AUTOMATIC)

    class Meta:
        unique_together = (('tag', 'ttype'),)

    def __str__(self):
        return "%s - %s" % (self.tag, self.ttype)

class HostGroup(models.Model):
    name = models.CharField(max_length=256, unique=True)
    creation_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "%s" % (self.name)
