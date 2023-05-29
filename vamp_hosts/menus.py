# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

def top_hosts(request):
    return '<span class="glyphicon glyphicon-blackboard" aria-hidden="true"></span> Hosts'

files_childs = (
    MenuItem("List All Hosts", reverse("hosts:list_hosts"), weight=10),
)

Menu.add_item("main", MenuItem(top_hosts,
    reverse("hosts:list_hosts"),
    weight=20,
    children=files_childs)
)
