""" import nessus scan files
"""

import uuid
import datetime
import os
import sys
import json
import uuid
import re

from tenable.sc import TenableSC

from vamp_api.models import TenableAPI
from vamp_main.utils import get_service_name
from vamp_scans.models import Host, Finding, Comment, Tag

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from django.conf import settings
from django.utils.timezone import make_aware

"""
{
  "pluginID": "58987",
  "severity": {
    "id": "4",
    "name": "Critical",
    "description": "Critical Severity"
  },
  "hasBeenMitigated": "1",
  "acceptRisk": "0",
  "recastRisk": "0",
  "ip": "10.130.76.6",
  "uuid": "",
  "port": "80",
  "protocol": "TCP",
  "pluginName": "PHP Unsupported Version Detection",
  "firstSeen": "1667890785",
  "lastSeen": "1675325895",
  "exploitAvailable": "No",
  "exploitEase": "",
  "exploitFrameworks": "",
  "synopsis": "The remote host contains an unsupported version of a web application scripting language.",
  "description": "According to its version, the installation of PHP on the remote host is no longer supported.\n\nLack of support implies that no new security patches for the product will be released by the vendor. As a result, it is likely to contain security vulnerabilities.",
  "solution": "Upgrade to a version of PHP that is currently supported.",
  "seeAlso": "http://php.net/eol.php\nhttps://wiki.php.net/rfc/releaseprocess",
  "riskFactor": "Critical",
  "stigSeverity": "",
  "vprScore": "",
  "vprContext": "[]",
  "baseScore": "10.0",
  "temporalScore": "",
  "cvssVector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
  "cvssV3BaseScore": "10.0",
  "cvssV3TemporalScore": "",
  "cvssV3Vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "cpe": "cpe:/a:php:php",
  "vulnPubDate": "-1",
  "patchPubDate": "-1",
  "pluginPubDate": "1336132800",
  "pluginModDate": "1670414400",
  "checkType": "remote",
  "version": "1.24",
  "cve": "",
  "bid": "",
  "xref": "IAVA #0001-A-0581",
  "pluginText": "<plugin_output>\n  Source              : X-Powered-By: PHP/7.2.21\n  Installed version   : 7.2.21\n  End of support date : 2020/11/30\n  Announcement        : http://php.net/supported-versions.php\n  Supported versions  : 8.0.x / 8.1.x\n</plugin_output>",
  "dnsName": "",
  "macAddress": "",
  "netbiosName": "",
  "operatingSystem": "Linux Kernel 2.6",
  "credentialed": "false",
  "ips": "10.130.76.6",
  "recastRiskRuleComment": "",
  "acceptRiskRuleComment": "",
  "hostUniqueness": "repositoryID,ip,dnsName",
  "hostUUID": "",
  "acrScore": "",
  "keyDrivers": "",
  "assetExposureScore": "",
  "uniqueness": "repositoryID,ip,dnsName",
  "family": {
    "id": "6",
    "name": "CGI abuses",
    "type": "active"
  },
  "repository": {
    "id": -1,
    "name": "Individual Scan",
    "description": "",
    "dataFormat": "IPv4"
  },
  "pluginInfo": "58987 (80/6) PHP Unsupported Version Detection"
}
"""


# load plugis
plugins = []
for plugin in settings.IMPORT_PLUGINS:
    print("loading import plugin: %s" % plugin)
    import_path = settings.IMPORT_PLUGINS_PATH
    sys.path.append(import_path)
    import_name = __import__(plugin)
    plugins.append(import_name.importPlugin())


def tenable(report):
    """create a new host entry if needed and add findings
    """
    host = {
        'name': '',
        'ip': '',
        'fqdn': '',
        'netbios_name': '',
        'rdns': '',
        'predicted_os': '',
        'os': '',
    }
    ### collect host information
    if 'netbiosName' in report and len(report['netbiosName'])>0:
        host['netbios_name'] = report['netbiosName']
    if 'operatingSystem' in report and len(report['operatingSystem'])>0:
        host['os'] = report['operatingSystem']
    if 'ip' in report and len(report['ip'])>0:
        host['ip'] = report['ip']
        host['name'] = report['ip']
    if 'dnsName' in report and len(report['dnsName'])>0:
        host['fqdn'] = report['dnsName']
        host['name'] = report['dnsName']
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
    ### collect finding
    svc_name = get_service_name(report['port'], report['protocol'].lower())
    scan_date = make_aware(datetime.datetime.fromtimestamp(int(report['firstSeen'])))
    finding = {
        'host': host_obj,
        'name': svc_name,
        'port': int(report['port']),
        'protocol': report['protocol'].lower(),
        'source': 'tenable',
        'service': svc_name,
        'severity': int(report['severity']['id']),
        'short': report['pluginName'],
        'scan_date': scan_date,
    }
    ### add description
    if 'description' in report:
        finding['description'] = report['description']
    else:
        finding['description'] = ''
    if 'pluginText' in report:
        finding['description'] += '\r\n\r\n'+report['pluginText']
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

    def handle(self, *args, **options):
        sev_dict = {
            'informational': 0,
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4,
        }
        tenableObjects = TenableAPI.objects.all()
        for tenableObj in tenableObjects:
            # get list of severities to fetch
            severity_list = tenableObj.severities.split(',')
            ask_severities = []
            for sev in severity_list:
                try:
                    ask_severities.append(sev_dict[sev.strip()])
                except Exception as error:
                    print(error)
                    continue
            if len(ask_severities)==0:
                ask_severities = [4,3,2,1]
            # connect to Tenable API
            sc = TenableSC(tenableObj.server, access_key=tenableObj.access_key, secret_key=tenableObj.secret_key)
            for sev in ask_severities:
                for vuln in sc.analysis.vulns(filters=[('severity', '=', '%s' % sev),]):
                    # start ingesting
                    tenable(vuln)
