from django.contrib import admin

from .models import Host, Finding, Contact, Comment, HostComment

# Register your models here.

admin.site.register(Host)
admin.site.register(Finding)
admin.site.register(Contact)
admin.site.register(Comment)
admin.site.register(HostComment)
