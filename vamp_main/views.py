# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count

from vamp_scans.models import Finding, Host

import random

def return_vulns_by_source(number):
    """return number of vulns by source
    """
    res = {}
    findings = Finding.objects.values_list('source').annotate(count=Count('id')).order_by('-count')[:10]
    xdata = []
    ydata = []
    for item in findings:
        xdata.append(item[0])
        ydata.append(item[1])
    #xdata.append('netsparker')
    #ydata.append(90324)
    #xdata.append('burp suite')
    #ydata.append(130324)
    extra_serie = {"tooltip": {"y_start": "", "y_end": ""},}
    chartdata = {'x': xdata, 'y': ydata, 'extra': extra_serie}
    charttype = "discreteBarChart"
    chartcontainer = 'piechart_container%i' % (number)
    data = {
        'charttype%i' % (number): charttype,
        'chartdata%i' % (number): chartdata,
        'chartcontainer%i' % (number): chartcontainer,
        'extra%i' % (number): {
            'showControls': False,
            'donut': True,
            'donutRatio': 0.6,
            'padAngle': 0.08,
        }
    }
    return data

@login_required
def home(request):
    cve_count = Finding.objects.filter(status=0).exclude(cve__isnull=True).exclude(cve__exact='').count()
    unique_cve_count = Finding.objects.filter(status=0).exclude(cve__isnull=True).exclude(cve__exact='').values('cve').distinct().count()
    unique_exploit_count = Finding.objects.filter(status=0, exploit_available__exact=True).values('short').distinct().count()
    exploit_count = Finding.objects.filter(status=0, exploit_available__exact=True).count()
    high_count = Finding.objects.filter(status=0, severity__gte=3).count()
    unique_high_count = Finding.objects.filter(status=0, severity__gte=3).values('short').distinct().count()
    context = {'cves': cve_count, 'ucves': unique_cve_count, 'uexploits': unique_exploit_count, 'exploits': exploit_count, 'uhighs': unique_high_count, 'highs': high_count}
    context.update(return_vulns_by_source(1))
    return render(request, 'vamp_main/index.html', context)
