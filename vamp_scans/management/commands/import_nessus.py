""" import nessus scan files
"""

from multiprocessing.pool import ThreadPool
import uuid
import datetime
import os
import sys
import xmltodict
import json
import uuid
import re

from vamp_scans.models import Host, Finding, Comment, Tag

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from django.conf import settings
from django.utils.timezone import make_aware

# load plugis
plugins = []
for plugin in settings.IMPORT_PLUGINS:
    print("loading import plugin: %s" % plugin)
    import_path = settings.IMPORT_PLUGINS_PATH
    sys.path.append(import_path)
    import_name = __import__(plugin)
    plugins.append(import_name.importPlugin())


def nessus(report):
    """create a new host entry if needed and add findings
    """
    host = {
        'name': report['@name'],
        'ip': None,
        'fqdn': '',
        'netbios_name': '',
        'rdns': '',
        'predicted_os': '',
        'os': 'unknown',
    }
    ### collect host information
    scan_date = None
    tag_list = report['HostProperties']['tag']
    for tag in tag_list:
        if tag['@name'] == 'host-rdns':
            host['rdns'] = tag['#text']
        if tag['@name'] == 'host-ip':
            host['ip'] = tag['#text']
        if tag['@name'] == 'os':
            host['os'] = tag['#text']
        if tag['@name'] == 'host-fqdns':
            fqdn_items = json.loads(tag['#text'])
            fqdn = fqdn_items[0]['FQDN']
            host['fqdn'] = fqdn
        if tag['@name'] == 'sinfp-ml-prediction':
            items = json.loads(tag['#text'])
            current_confidence = 0
            current_prediction = ''
            for item in items:
                if item['confidence'] > current_confidence:
                    current_confidence = item['confidence']
                    current_prediction = item['predicted-os']
            host['predicted_os'] = current_prediction
        if tag['@name'] == 'netbios-name':
            host['netbios_name'] = tag['#text']
        if tag['@name'] == 'HOST_END_TIMESTAMP':
            scan_date = make_aware(datetime.datetime.fromtimestamp(int(tag['#text'])))
    if scan_date is None:
        scan_date = make_aware(datetime.datetime.now())
    ### process import plugins on host item
    for plugin in plugins:
        host = plugin.process_host(host)
    ### get or create host entry
    host_obj, created = Host.objects.get_or_create(ip=host['ip'], fqdn=host['fqdn'], netbios_name=host['netbios_name'], rdns=host['rdns'])
    ### update existing entry
    if not created:
        if host_obj.name == '':
            host_obj.name = host['name']
        if host_obj.os == 'unknown':
            host_obj.os = host['os']
        if host_obj.predicted_os is None or host_obj.predicted_os == '':
            host_obj.predicted_os = host['predicted_os']
    else:
        host_obj.name = host['name']
        host_obj.os = host['os']
        host_obj.predicted_os = host['predicted_os']
    host_obj.save()
    ### collect findings
    issues = report['ReportItem']
    for issue in issues:
        ### skip open port findings.
        if issue['@pluginFamily'] == 'Port scanners':
            continue
        svc_name = issue['@svc_name'].replace('?','')
        finding = {
            'host': host_obj,
            'name': svc_name,
            'port': issue['@port'],
            'protocol': issue['@protocol'].lower(),
            'source': 'nessus',
            'service': svc_name,
            'severity': int(issue['@severity']),
            'short': issue['@pluginName'],
            'scan_date': scan_date,
        }
        if 'plugin_output' in issue:
            finding['description'] = issue['plugin_output']
        else:
            finding['description'] = ''
        ### find CVE string
        cve_regex = re.compile('CVE-[0-9]+-[0-9]+')
        match = cve_regex.search(finding['short'])
        if match:
            finding['cve'] = match.group()
        else:
            match = cve_regex.search(finding['description'])
            if match:
                finding['cve'] = match.group()
        ### process import plugins
        for plugin in plugins:
            finding = plugin.process_finding(finding)
        ### create finding UUID
        fuuid = uuid.uuid5(uuid.NAMESPACE_DNS, "%s%s%snessus%s%s%s%s%s" % (host_obj, svc_name, finding['protocol'], finding['port'], svc_name, finding['severity'], finding['short'], finding['description']))
        finding['uuid'] = fuuid
        ### get or create finding entry
        new_finding = True
        finding_obj = None
        ### check for same finding with given status
        try:
            finding_obj = Finding.objects.get(uuid=fuuid)
            new_finding = False
        except Finding.DoesNotExist:
            new_finding = True
        # finding already exists
        if new_finding is False and finding_obj.status != 1: # workaround, false, ignore, exception, open -> leave as is
            finding_obj.save() # update last_seen field
        elif new_finding is False and finding_obj.status == 1: # was patched but found again -> re-open
            # remediation was also earlier than current scan
            if finding_obj.date_remediated < scan_date:
                comment = {
                    'ctext': 'issue was found again, finding re-opend!',
                    'author': User.objects.get(username='admin'), # admin user
                    'finding': finding_obj,
                }
                comment_obj = Comment.objects.create(**comment)
                finding_obj.status = 0
                finding_obj.save() # update last_seen field
        elif new_finding is True: # nothing found -> create new finding
            finding_obj = Finding.objects.create(**finding)
            finding_obj.save()


class Command(BaseCommand):
    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)

    def add_arguments(self, parser):
        # Positional arguments
        parser.add_argument('filename', type=str)

    def handle(self, *args, **options):
        fn = options['filename']
        if not os.path.exists(fn):
            print('file does not exist!')
            sys.exit(1)
        if not fn.endswith('.nessus'):
            print('file is not a nessus scan result XML!')
            sys.exit(1)
        ### read file content
        with open(fn) as fp:
            data = xmltodict.parse(fp.read())
        print('scanning file with 10 threads ...')
        ### nessus report data
        reports = data['NessusClientData_v2']['Report']['ReportHost']
        ### start ingesting
        pool = ThreadPool(processes=10)  # increasing this number may speed things up
        pool.map(nessus, reports)
