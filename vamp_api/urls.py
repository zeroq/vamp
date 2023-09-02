
from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns

from vamp_api import finding_views
from vamp_api import host_views
from vamp_api import exceptions_views
from vamp_api import settings_views

urlpatterns = [
    # hosts APIs
    path('v1/hosts/', host_views.list_hosts, name='list_hosts'),
    path('v1/host/<int:hostid>/findings/', host_views.list_host_findings, name='list_host_findings'),
    path('v1/host/<int:hostid>/tags/<str:ttype>/', host_views.host_tags_list.as_view(), name='host_tags_list'),
    path('v1/host/<int:hostid>/findings/<int:severity>/severity/', host_views.list_host_findings_severity, name='list_host_findings_severity'),
    path('v1/host/<int:hostid>/findings/<int:status>/status/', host_views.list_host_findings_status, name='list_host_findings_status'),
    path('v1/host/<int:hostid>/comments/', host_views.list_host_comments.as_view(), name='list_host_comments'),
    # findings APIs
    path('v1/findings/', finding_views.list_findings, name='list_findings'),
    path('v1/findings/<int:findingid>/details/', finding_views.get_finding_details, name='get_finding_details'),
    path('v1/findings/<int:severity>/severity/', finding_views.list_findings_severity, name='list_findings_severity'),
    path('v1/findings/<int:status>/status/', finding_views.list_findings_status, name='list_findings_status'),
    path('v1/findings/<int:findingid>/hosts/open/', finding_views.list_findings_hosts, name='list_findings_hosts'),
    path('v1/findings/<int:findingid>/hosts/remediated/', finding_views.list_findings_hosts_remediated, name='list_findings_hosts_remediated'),
    path('v1/findings/<int:findingid>/reopen/', finding_views.reopen_finding, name='reopen_finding'),
    path('v1/findings/<int:findingid>/comments/', finding_views.list_finding_comments.as_view(), name='list_finding_comments'),
    # exceptions APIs
    path('v1/exceptions/', exceptions_views.list_open_exceptions, name='list_open_exceptions'),
    path('v1/exceptions/granted/', exceptions_views.list_granted_exceptions, name='list_granted_exceptions'),
    path('v1/exceptions/expired/', exceptions_views.list_expired_exceptions, name='list_expired_exceptions'),
    path('v1/exceptions/<int:hostid>/', exceptions_views.list_exceptions_host, name='list_exceptions_host'),
    # tenable api
    path('v1/endpoints/tenable/', settings_views.list_tenable_endpoints, name='list_tenable_endpoints'),
    # statistics api
    path('v1/findings/top/open/', settings_views.top_findings_by_asset, name='top_findings_by_asset'),
    path('v1/hosts/top/vulnerable/', settings_views.top_vulnerable_hosts, name='top_vulnerable_hosts'),
]

urlpatterns = format_suffix_patterns(urlpatterns)
