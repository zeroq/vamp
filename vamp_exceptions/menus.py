# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

from vamp_exceptions.models import Exceptions, Ignore

def top_hosts(request):
    return '<span class="glyphicon glyphicon-alert " aria-hidden="true"></span> Exceptions'

def open_exceptions(request):
    count = Exceptions.objects.filter(approved=False).count()
    return 'Open Exceptions <span class="label label-primary">%s</span>' % count

def open_ignore(request):
    count = Ignore.objects.filter(approved=False).count()
    return 'Open Ignore Requests <span class="label label-primary">%s</span>' % count

files_childs = (
    MenuItem(open_exceptions, reverse("exceptions:list_exceptions"), weight=10),
    MenuItem("Granted Exceptions", reverse("exceptions:list_granted_exceptions"), weight=20),
    MenuItem("Expired Exceptions", reverse("exceptions:list_expired_exceptions"), weight=30),
    MenuItem(open_ignore, reverse("exceptions:list_ignore_requests"), weight=40, separator=True),
    MenuItem("Granted Ignore Requests", reverse("exceptions:list_granted_ignore"), weight=50),
)

Menu.add_item("main", MenuItem(top_hosts,
    reverse("exceptions:list_exceptions"),
    weight=50,
    children=files_childs)
)
