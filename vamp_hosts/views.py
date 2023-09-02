
from datetime import datetime

from django.shortcuts import render, redirect
from django.contrib import messages
from django.urls import reverse
from django.utils.html import format_html
from django.contrib.auth.decorators import login_required

from vamp_scans.models import Host, Finding, Comment, Tag
from vamp_scans.forms import AddTagForm
from vamp_exceptions.models import Exceptions

# Create your views here.

@login_required
def list_hosts(request):
    """List all hosts
    """
    context = {}
    return render(request, 'vamp_hosts/list_hosts.html', context)

@login_required
def host_add_tag(request, hostid):
    """Add a tag to a host
    """
    if request.method == 'POST':
        form = AddTagForm(request.POST)
        if form.is_valid():
            try:
                host_obj = Host.objects.get(id=hostid)
            except Host.DoesNotExist:
                messages.error(request, 'Host not found!')
                return render(request, 'vamp_hosts/list_hosts.html', context)
            tagname = form.cleaned_data['tag']
            link = form.cleaned_data['link']
            description = form.cleaned_data['description']
            # get or create a new tag entry
            tobj, tcreated = Tag.objects.get_or_create(**{'tag': tagname, 'ttype': 1})
            if tcreated is True:
                tobj.link = link
                tobj.description = description
                tobj.save()
            host_obj.tags.add(tobj)
            host_obj.save()
        else:
            messages.error(request, format_html('Invalid form data! %s' % form.errors))
    return redirect(reverse('hosts:view_host', kwargs={'hostid': hostid}))

@login_required
def view_host(request, hostid):
    context = {}
    try:
        host_obj = Host.objects.get(id=hostid)
        context['host'] = host_obj
    except Host.DoesNotExist:
        messages.error(request, 'Host not found!')
        return render(request, 'vamp_hosts/list_hosts.html', context)
    context['crit_count'] = Finding.objects.filter(host_id=host_obj.id, status=0, severity=4).count()
    context['high_count'] = Finding.objects.filter(host_id=host_obj.id, status=0, severity=3).count()
    context['med_count'] = Finding.objects.filter(host_id=host_obj.id, status=0, severity=2).count()
    context['low_count'] = Finding.objects.filter(host_id=host_obj.id, status=0, severity=1).count()
    context['info_count'] = Finding.objects.filter(host_id=host_obj.id, status=0, severity=0).count()
    context['waiting_exception'] = Finding.objects.filter(host_id=hostid, status=6).count()
    context['have_exception'] = Exceptions.objects.filter(host=host_obj).count()
    activeTab = ''
    if context['crit_count'] > 0:
        activeTab = 'critical'
    elif context['high_count'] > 0:
        activeTab = 'high'
    elif context['med_count'] > 0:
        activeTab = 'medium'
    elif context['low_count'] > 0:
        activeTab = 'low'
    elif context['info_count'] > 0:
        activeTab = 'info'
    else:
        activeTab = 'critical'
    context['activetab'] = activeTab
    context['tagform'] = AddTagForm()
    return render(request, 'vamp_hosts/view_host.html', context)

@login_required
def reset_exception_request(request, hostid, findingid):
    hostid = int(hostid)
    findingid = int(findingid)
    context = {}
    try:
        host_obj = Host.objects.get(id=hostid)
    except Host.DoesNotExist:
        messages.error(request, 'Host not found!')
        return render(request, 'vamp_hosts/list_hosts.html', context)
    try:
        finding_obj = Finding.objects.get(id=findingid)
    except Finding.DoesNotExist:
        messages.error(request, 'Finding not found!')
        return render(request, 'vamp_hosts/list_hosts.html', context)
    # check if finding belongs to host
    if finding_obj.host != host_obj:
        messages.error(request, 'Finding does not belong to host!')
        return redirect(reverse('hosts:view_host', kwargs={'hostid': hostid}))
    # fetch exception object
    try:
        exc_obj = Exceptions.objects.get(finding=finding_obj, host=host_obj)
    except Exceptions.DoesNotExist:
        messages.error(reuqest, 'Exception not found!')
        return render(request, 'vamp_hosts/list_hosts.html', context)
    # delete exceptions request
    exc_obj.delete()
    # reset finding to open
    finding_obj.status = 0
    finding_obj.date_remediated = None
    finding_obj.save()
    return redirect(reverse('hosts:view_host', kwargs={'hostid': hostid}))

@login_required
def view_ops_finding(request, hostid, findingid, operation):
    hostid = int(hostid)
    findingid = int(findingid)
    context = {}
    try:
        host_obj = Host.objects.get(id=hostid)
    except Host.DoesNotExist:
        messages.error(request, 'Host not found!')
        return render(request, 'vamp_hosts/list_hosts.html', context)
    try:
        finding_obj = Finding.objects.get(id=findingid)
    except Finding.DoesNotExist:
        messages.error(request, 'Finding not found!')
        return render(request, 'vamp_hosts/list_hosts.html', context)
    # check if finding belongs to host
    if finding_obj.host != host_obj:
        messages.error(request, 'Finding does not belong to host!')
        return redirect(reverse('hosts:view_host', kwargs={'hostid': hostid}))
    # change status
    changed = False
    if operation == 'open':
        messages.info(request, 'Finding set to: %s' % operation)
        finding_obj.status = 0
        finding_obj.date_remediated = None
        finding_obj.save()
        changed = True
    elif operation == 'patch':
        messages.info(request, 'Finding set to: %s' % operation)
        finding_obj.status = 1
        finding_obj.date_remediated = datetime.now()
        finding_obj.save()
        changed = True
    elif operation == 'workaround':
        messages.info(request, 'Finding set to: %s' % operation)
        finding_obj.status = 2
        finding_obj.date_remediated = datetime.now()
        finding_obj.save()
        changed = True
    elif operation == 'exception':
        messages.info(request, 'Finding set to: %s' % operation)
        finding_obj.status = 3
        finding_obj.date_remediated = datetime.now()
        finding_obj.save()
        changed = True
    elif operation == 'false':
        messages.info(request, 'Finding set to: %s' % operation)
        finding_obj.status = 4
        finding_obj.date_remediated = datetime.now()
        finding_obj.save()
        changed = True
    elif operation == 'ignore':
        messages.info(request, 'Finding set to: %s' % operation)
        finding_obj.status = 5
        finding_obj.date_remediated = datetime.now()
        finding_obj.save()
        changed = True
    else:
        messages.error(request, 'Unknown operation: %s (ignoring the request)' % operation)
        changed = False
    if changed is True:
        # prepare comment
        comm = {
            'author': request.user,
            'ctext': 'changed status to: %s (host %s)' % (operation, host_obj.name),
            'finding': finding_obj
        }
        c = Comment(**comm)
        c.save()
    return redirect(reverse('hosts:view_host', kwargs={'hostid': hostid}))
