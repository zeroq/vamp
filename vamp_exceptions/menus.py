# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

from vamp_exceptions.models import Exceptions, Ignore

def top_hosts(request):
    return '<span class="glyphicon glyphicon-alert " aria-hidden="true"></span> Exceptions'

def open_exceptions(request):
    count = Exceptions.objects.filter(approved=False).count()
    return 'Open Exceptions <span class="label label-primary">%s</span>' % count

def granted_exceptions(request):
    count = Exceptions.objects.filter(approved=True, still_valid=True).count()
    return 'Granted Exceptions <span class="label label-warning">%s</span>' % count

def expired_exceptions(request):
    count = Exceptions.objects.filter(approved=True, still_valid=False).count()
    return 'Expired Exceptions <span class="label label-danger">%s</span>' % count

def open_ignore(request):
    count = Ignore.objects.filter(approved=False).count()
    return 'Open Ignore Requests <span class="label label-primary">%s</span>' % count

def granted_ignore(request):
    count = Ignore.objects.filter(approved=True).count()
    return 'Granted Ignore Requests <span class="label label-warning">%s</span>' % count


files_childs = (
    MenuItem(open_exceptions, reverse("exceptions:list_exceptions"), weight=10),
    MenuItem(granted_exceptions, reverse("exceptions:list_granted_exceptions"), weight=20),
    MenuItem(expired_exceptions, reverse("exceptions:list_expired_exceptions"), weight=30),
    MenuItem(open_ignore, reverse("exceptions:list_ignore_requests"), weight=40, separator=True),
    MenuItem(granted_ignore, reverse("exceptions:list_granted_ignore"), weight=50),
)

Menu.add_item("main", MenuItem(top_hosts,
    reverse("exceptions:list_exceptions"),
    weight=50,
    children=files_childs)
)
