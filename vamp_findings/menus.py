# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from django.db.models import Q, Prefetch, Count
from menu import Menu, MenuItem

from vamp_scans.models import Finding

def all_findings(request):
    count = Finding.objects.all().count()
    return 'All Findings <span class="label label-primary">%s</span>' % count

def all_open_findings(request):
    count = Finding.objects.filter(~Q(severity=0), status=0).count()
    return 'All Open Findings <span class="label label-primary">%s</span>' % count

def all_critical_findings(request):
    count = Finding.objects.filter(severity=4).count()
    return 'Critical Findings <span class="label label-default">%s</span>' % count

def all_high_findings(request):
    count = Finding.objects.filter(severity=3).count()
    return 'High Findings <span class="label label-danger">%s</span>' % count

def all_medium_findings(request):
    count = Finding.objects.filter(severity=2).count()
    return 'Medium Findings <span class="label label-warning">%s</span>' % count

def all_low_findings(request):
    count = Finding.objects.filter(severity=1).count()
    return 'Low Findings <span class="label label-success">%s</span>' % count

def all_informative_findings(request):
    count = Finding.objects.filter(severity=0).count()
    return 'Informative Findings <span class="label label-info">%s</span>' % count

def top_findings(request):
    return '<span class="glyphicon glyphicon-list" aria-hidden="true"></span> Findings'


files_childs = (
    MenuItem(all_findings, reverse("findings:list_findings"), weight=100),
    MenuItem(all_open_findings, reverse("findings:list_findings_status", kwargs={'status':0}), weight=10),
    MenuItem(all_critical_findings, reverse("findings:list_findings_severity", kwargs={'severity':4}), weight=20),
    MenuItem(all_high_findings, reverse("findings:list_findings_severity", kwargs={'severity':3}), weight=30),
    MenuItem(all_medium_findings, reverse("findings:list_findings_severity", kwargs={'severity':2}), weight=40),
    MenuItem(all_low_findings, reverse("findings:list_findings_severity", kwargs={'severity':1}), weight=50),
    MenuItem(all_informative_findings, reverse("findings:list_findings_severity", kwargs={'severity':0}), weight=99),
)

Menu.add_item("main", MenuItem(top_findings,
    reverse("findings:list_findings"),
    weight=30,
    children=files_childs)
)
