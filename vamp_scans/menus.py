# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

def top_home(request):
    return '<span class="glyphicon glyphicon-upload" aria-hidden="true"></span> Import'

home_childs = (
    MenuItem("Import Nessus XML", reverse("scans:import_nessus"), weight=10),
    MenuItem("Configure Tenable API", reverse("scans:configure_tenable_api"), weight=100),
    #MenuItem("Upload File", reverse("upload_file"), weight=20),
)

Menu.add_item("main", MenuItem(top_home,
    reverse("scans:import_nessus"),
    weight=40,
    children=home_childs)
)
