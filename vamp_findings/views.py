
from datetime import datetime

from django.shortcuts import render, redirect
from django.contrib import messages
from django.urls import reverse
from django.contrib.auth.decorators import login_required

from vamp_scans.models import Finding, Comment, HostComment
from vamp_exceptions.models import Exceptions

# Create your views here.

@login_required
def change_finding_for_host(request, findingid, status):
    """change the status of the finding for given host
    """
    context = {}
    # get finding object
    try:
        obj = Finding.objects.get(id=findingid)
    except Finding.DoesNotExist:
        messages.error(request, 'Finding not found!')
        return render(request, 'vamp_findings/list_findings.html', context)
    # prepare comment
    comment = {
        'author': request.user,
        'ctext': ''
    }
    changed = False
    if status == 'open':
        obj.status = 0
        obj.date_remediated = None
        obj.save()
        messages.info(request, 'Finding changed to "%s" for host %s!' % (status, obj.host.name))
        changed = True
    else:
        messages.error(request, 'Unknown Finding status: %s' % status)
        changed = False
    if changed is True:
        # create finding comment
        comment['finding'] = obj
        comment['ctext'] = 'changed status to: %s (%s)' % (status, obj.host.name)
        c = Comment(**comment)
        c.save()
        # create host comment
        del comment['finding']
        comment['host'] = obj.host
        c = HostComment(**comment)
        c.save()
    return redirect(reverse('findings:view_finding', kwargs={'findingid': findingid}))



@login_required
def change_finding_affected_hosts(request, findingid, status):
    """change the status of the finding for all affected hosts
    """
    context = {}
    try:
        obj = Finding.objects.get(id=findingid)
    except Finding.DoesNotExist:
        messages.error(request, 'Finding not found!')
        return render(request, 'vamp_findings/list_findings.html', context)
    try:
        objs = Finding.objects.filter(service=obj.service, port=obj.port, severity=obj.severity, short=obj.short, description=obj.description)
    except Exception as error:
        messages.error(request, 'Finding not found! (%s)' % error)
        return render(request, 'vamp_findings/list_findings.html', context)
    # prepare comment TODO: remove not used
    #comment = {
    #    'author': request.user,
    #    'ctext': ''
    #}
    # remove exception entries that were created for all at once
    for entry in objs:
        Exceptions.objects.filter(finding=entry, approved=True, reason='Grant all exception').delete()
        # add host comment
        comm = {
            'host': entry.host,
            'author': request.user,
            'ctext': 'global exception for %s removed' % entry.name
        }
        c = HostComment(**comm)
        c.save()
    # change status of all affected hosts
    changed = False
    if status == 'open':
        # update findings entries
        objs.update(status=0, date_remediated=None)
        messages.info(request, 'Finding changed to "%s" for all affected hosts!' % status)
        changed = True
    elif status == 'patch':
        objs.update(status=1, date_remediated=datetime.now())
        messages.info(request, 'Finding changed to "%s" for all affected hosts!' % status)
        changed = True
    elif status == 'workaround':
        objs.update(status=2, date_remediated=datetime.now())
        messages.info(request, 'Finding changed to "%s" for all affected hosts!' % status)
        changed = True
    elif status == 'exception':
        # create exception entries
        for entry in objs:
            host = entry.host
            exc_entry = {
                'finding': entry,
                'host': host,
                'requestor': request.user,
                'approver': request.user,
                'reason': 'Grant all exception',
                'duration': 90,
                'approved': True,
                'still_valid': True
            }
            e = Exceptions(**exc_entry)
            e.save()
            # add host comment
            comm = {
                'host': host,
                'author': request.user,
                'ctext': 'global exception for %s granted' % entry.name
            }
            c = HostComment(**comm)
            c.save()
        # update finding entries
        objs.update(status=3, date_remediated=datetime.now())
        messages.info(request, 'Finding changed to "%s" for all affected hosts!' % status)
        changed = True
    elif status == 'false':
        objs.update(status=4, date_remediated=datetime.now())
        messages.info(request, 'Finding changed to "%s" for all affected hosts!' % status)
        changed = True
    elif status == 'ignore':
        objs.update(status=5, date_remediated=datetime.now())
        messages.info(request, 'Finding changed to "%s" for all affected hosts!' % status)
        changed = True
    else:
        messages.error(request, 'Unknown Finding status: %s' % status)
        changed = False
    if changed is True:
        for entry in objs:
            # prepare comment
            comm = {
                'author': request.user,
                'ctext': 'changed status to: %s (all affected hosts)' % status,
                'finding': entry
            }
            c = Comment(**comm)
            c.save()
    return redirect(reverse('findings:view_finding', kwargs={'findingid': findingid}))

@login_required
def list_findings(request):
    context = {}
    return render(request, 'vamp_findings/list_findings.html', context)

@login_required
def list_findings_status(request, status):
    context = {'status': status}
    return render(request, 'vamp_findings/list_findings_status.html', context)

@login_required
def list_findings_severity(request, severity):
    context = {'severity': severity}
    return render(request, 'vamp_findings/list_findings_severity.html', context)

@login_required
def view_finding(request, findingid):
    context = {}
    try:
        finding_obj = Finding.objects.get(id=findingid)
        context['finding'] = finding_obj
    except Finding.DoesNotExist:
        messages.error(request, 'Finding not found!')
        return render(request, 'vamp_findings/list_findings.html', context)
    context['description'] = finding_obj.description.split('\n')
    ### exploit avail
    if finding_obj.exploit_available is True:
        context['exploit_available'] = '<span class="label label-danger">True</span>'
    else:
        context['exploit_available'] = '<span class="label label-success">False</span>'
    ### exploited
    if finding_obj.exploited_in_the_wild is True:
        context['exploited_in_the_wild'] = '<span class="label label-danger">True</span>'
    else:
        context['exploited_in_the_wild'] = '<span class="label label-success">False</span>'
    ### escalated
    if finding_obj.escalated is True:
        context['escalated'] = '<span class="label label-danger">True</span>'
    else:
        context['escalated'] = '<span class="label label-success">False</span>'
    ### severity
    if finding_obj.severity == 4:
        context['severity'] = '<span class="label label-default">Critical</span>'
    elif finding_obj.severity == 3:
        context['severity'] = '<span class="label label-danger">High</span>'
    elif finding_obj.severity == 2:
        context['severity'] = '<span class="label label-warning">Medium</span>'
    elif finding_obj.severity == 1:
        context['severity'] = '<span class="label label-success">Low</span>'
    else:
        context['severity'] = '<span class="label label-info">Information</span>'
    ### status
    if finding_obj.status == 0:
        context['status'] = '<span class="label label-danger">Open</span>'
    elif finding_obj.status == 1:
        context['status'] = '<span class="label label-success">Patched</span>'
    elif finding_obj.status == 2:
        context['status'] = '<span class="label label-warning">Workaround</span>'
    elif finding_obj.status == 3:
        context['status'] = '<span class="label label-danger">Exception</span>'
    elif finding_obj.status == 4:
        context['status'] = '<span class="label label-success">False Positive</span>'
    elif finding_obj.status == 5:
        context['status'] = '<span class="label label-danger">Ignore</span>'

    return render(request, 'vamp_findings/view_finding.html', context)
