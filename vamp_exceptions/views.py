
from django.shortcuts import render, redirect
from django.contrib import messages
from django.urls import reverse
from django.utils.html import format_html
from django.contrib.auth.decorators import login_required

from vamp_scans.models import Host, Finding, HostComment
from vamp_exceptions.models import Exceptions

# Create your views here.

@login_required
def list_exceptions(request):
    """List all exceptions
    """
    context = {}
    return render(request, 'vamp_exceptions/list_exceptions.html', context)

@login_required
def list_granted_exceptions(request):
    """List all granted exceptions
    """
    context = {}
    return render(request, 'vamp_exceptions/list_granted_exceptions.html', context)

@login_required
def list_expired_exceptions(request):
    """List all expired exceptions
    """
    context = {}
    return render(request, 'vamp_exceptions/list_expired_exceptions.html', context)

@login_required
def add_request(request, hostid):
    """Add Exception Request to Host
    """
    if request.method == 'POST':
        # 'customreason': ['My Reason'], 'dayrange': ['30'], 'hiddenhostid': ['2977'], 'hiddenfindingid': ['155197']
        if int(hostid) == int(request.POST['hiddenhostid']):
            findingid = int(request.POST['hiddenfindingid'])
            dayrange = int(request.POST['dayrange'])
            reason = request.POST['customreason']
            requestor = request.user
            try:
                host_obj = Host.objects.get(id=hostid)
            except Host.DoesNotExist:
                messages.error(request, 'Host does not exist!')
                return redirect(reverse('hosts:view_host', kwargs={'hostid': hostid}))
            try:
                finding_obj = Finding.objects.get(id=findingid)
            except Finding.DoesNotExist:
                messages.error(request, 'Finding does not exist!')
                return redirect(reverse('hosts:view_host', kwargs={'hostid': hostid}))
            # create request object
            exrequest = Exceptions.objects.create(**{'finding': finding_obj, 'host': host_obj, 'requestor': requestor, 'reason': reason, 'duration': dayrange})
            # change status to progress
            finding_obj.status = 6
            finding_obj.save()
            messages.info(request, 'Exception request created!')
        else:
            messages.error(request, 'Wrong host ID submitted! %s - %s' % (hostid, request.POST['hiddenhostid']))
    return redirect(reverse('hosts:view_host', kwargs={'hostid': hostid}))

@login_required
def grant_request(request, exceptionid):
    """Grant Exception request
    """
    context = {}
    # get exception object
    try:
        exc_obj = Exceptions.objects.get(id=exceptionid, approved=False)
    except Exceptions.DoesNotExist:
        messages.error(request, 'Exception does not exist!')
        return redirect(reverse('exceptions:list_exceptions'))
    # set to granted
    # TODO: verify user is admin
    exc_obj.approved = True
    exc_obj.approver = request.user
    exc_obj.still_valid = True # initially true, will change with cronjob
    exc_obj.save()
    # get finding object
    try:
        fin_obj = Finding.objects.get(id=exc_obj.finding.id)
    except Finding.DoesNotExist:
        messages.error(request, 'Exception does not exist!')
        return redirect(reverse('exceptions:list_exceptions'))
    # set to exception
    fin_obj.status = 3
    fin_obj.save()
    # prepare comment
    comm = {
        'author': request.user,
        'ctext': 'Exception (%s) granted for %s days.' % (exc_obj.finding.short, exc_obj.duration),
        'host': exc_obj.host
    }
    c = HostComment(**comm)
    c.save()
    messages.info(request, 'Exception successfully granted!')
    return render(request, 'vamp_exceptions/list_exceptions.html', context)

@login_required
def reject_request(request, exceptionid):
    """Reject Exception Request
    """
    context = {}
    # get exception object
    # TODO: verify user is responsible for host/finding or admin
    try:
        exc_obj = Exceptions.objects.get(id=exceptionid)
    except Exceptions.DoesNotExist:
        messages.error(request, 'Exception does not exist!')
        return redirect(reverse('exceptions:list_exceptions'))
    # get finding object
    try:
        fin_obj = Finding.objects.get(id=exc_obj.finding.id)
    except Finding.DoesNotExist:
        messages.error(request, 'Exception does not exist!')
        return redirect(reverse('exceptions:list_exceptions'))
    # prepare comment
    comm = {
        'author': request.user,
        'ctext': 'Exception (%s) rejected!' % exc_obj.finding.short,
        'host': exc_obj.host
    }
    c = HostComment(**comm)
    c.save()
    # reset status of finding back to open
    fin_obj.status = 0
    fin_obj.save()
    # delete exception object
    exc_obj.delete()
    messages.info(request, 'Exception successfully rejected!')
    return render(request, 'vamp_exceptions/list_exceptions.html', context)
