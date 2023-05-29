# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

def top_hosts(request):
    return '<span class="glyphicon glyphicon-alert " aria-hidden="true"></span> Exceptions'

files_childs = (
    MenuItem("Open Exceptions", reverse("exceptions:list_exceptions"), weight=10),
    MenuItem("Granted Exceptions", reverse("exceptions:list_granted_exceptions"), weight=20),
    MenuItem("Expired Exceptions", reverse("exceptions:list_expired_exceptions"), weight=30),
)

Menu.add_item("main", MenuItem(top_hosts,
    reverse("exceptions:list_exceptions"),
    weight=50,
    children=files_childs)
)
