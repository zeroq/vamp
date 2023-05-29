# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

import xmltodict
from multiprocessing.pool import ThreadPool

from django.shortcuts import render
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.utils.html import format_html

from vamp_api.models import TenableAPI
from vamp_scans.forms import UploadNessusFileForm, ConfigureTenableAPIForm
from vamp_scans.management.commands.import_nessus import nessus

# Create your views here.

@login_required
def delete_tenable_api(request, tid):
    """Remove Tenable API endpoint
    """
    try:
        tobj = TenableAPI.objects.get(id=tid)
    except TenableAPI.DoesNotExist:
        messages.error(request, 'Entry does not exist!')
        return HttpResponseRedirect(reverse('scans:configure_tenable_api'))
    tobj.delete()
    messages.info(request, 'Entry successfully deleted!')
    return HttpResponseRedirect(reverse('scans:configure_tenable_api'))

@login_required
def configure_tenable_api(request):
    context = {}
    if request.method == 'POST':
        form = ConfigureTenableAPIForm(request.POST)
        if form.is_valid():
            apiobj = form.save()
            messages.info(request, 'Entry created successfull!')
        else:
            messages.error(request, format_html('Entry creation failed! %s' % form.errors))
        return HttpResponseRedirect(reverse('scans:configure_tenable_api'))
    else:
        form = ConfigureTenableAPIForm()
    context['form'] = form
    return render(request, 'vamp_scans/configure_tenable.html', context)


@login_required
def import_nessus(request):
    context = {}
    if request.method == 'POST':
        form = UploadNessusFileForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                # tranform XML to Dictuionary
                data = xmltodict.parse(request.FILES['file'])
                # nessus report data
                reports = data['NessusClientData_v2']['Report']['ReportHost']
                # create threads for performance
                pool = ThreadPool(processes=10)
                pool.map(nessus, reports)
                messages.info(request, 'Upload successfull!')
            except Exception as error:
                messages.error(request, "ERROR: %s" % error)
        else:
            messages.error(request, format_html('Upload failed! %s' % form.errors))
        return HttpResponseRedirect(reverse('scans:import_nessus'))
    else:
        form = UploadNessusFileForm()
    context['form'] = form
    return render(request, 'vamp_scans/import_nessus.html', context)
