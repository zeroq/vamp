
from itertools import chain

from vamp_scans.models import Host, Finding, Comment, Tag, HostComment
from vamp_exceptions.models import Exceptions
from vamp_api.models import TenableAPI
from vamp_api.serializers import HostSerializer, FindingSerializer, VulnHostSerializer, TopFindingSerializer, FindingDetailsSerializer, FindingHostsSerializer, CommentSerializer, TagSerializer, TenableAPISerializer, ExceptionSerializer, HostCommentSerializer
from vamp_api.pagination import CustomPaginator
from vamp_api.utils import get_ordering_vars

from rest_framework import generics, renderers
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes

from django.shortcuts import render
from django.http import JsonResponse, HttpResponse, HttpResponseRedirect
from django.db.models import Q, Prefetch, Count

# Create your views here.


### HOST API ####

@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
class host_tags_list(APIView):
    """List all tags for given host id
    """
    def get(self, request, hostid=None, ttype=None, format=None):
        if ttype == 'manual':
            queryset = Tag.objects.filter(host__id=hostid, ttype=1)
        elif ttype == 'automatic':
            queryset = Tag.objects.filter(host__id=hostid, ttype=2)
        else:
            queryset = Tag.objects.filter(host__id=hostid)
        serializer = TagSerializer(queryset, many=True)
        return Response(serializer.data)

class list_host_comments(generics.ListAPIView):
    """List all comments for a host
    """
    pagination_class = CustomPaginator
    serializer_class = HostCommentSerializer

    def get_queryset(self):
        hostid= self.kwargs['hostid']
        return HostComment.objects.filter(host__id=hostid).order_by('-creation_time')


### FINDING API ###

@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
class list_finding_comments(generics.ListAPIView):
    """List all comments for a finding
    """
    pagination_class = CustomPaginator
    serializer_class = CommentSerializer

    def get_queryset(self):
        findingid= self.kwargs['findingid']
        return Comment.objects.filter(finding__id=findingid).order_by('-creation_time')


@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def reopen_finding(request, findingid, format=None):
    """Set the status of given Finding back to open
    """
    result = {
        "status": True, "code": 404, "message": "failed to modify status!"
    }
    try:
        obj = Finding.objects.get(id=findingid)
    except Finding.DoesNotExist:
        return JsonResponse(result)
    obj.status = 0
    obj.save()
    result["code"] = 200
    result["message"] = "changed to open"
    return JsonResponse(result)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_findings_hosts_remediated(request, findingid, format=None):
    """Get list of hosts with remediation done
    """
    paginator = CustomPaginator()
    result = {
        "status": True, "code": 404, "next": None, "previous": None, "count": 0, "iTotalRecords": 0, "iTotalDisplayRecords": 0, "results": []
    }
    try:
        obj = Finding.objects.get(id=findingid)
    except Finding.DoesNotExist:
        return JsonResponse(result)
    try:
        # only remediated findings
        objs = Finding.objects.filter(service=obj.service, port=obj.port, severity=obj.severity, short=obj.short, description=obj.description).exclude(status=0)
    except Exception as error:
        print(error)
        return JsonResponse(result)
    hosts = paginator.paginate_queryset(objs, request)
    serializer = FindingHostsSerializer(instance=hosts, many=True)
    return paginator.get_paginated_response(serializer.data)


@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_findings_hosts(request, findingid, format=None):
    """Get list of hosts still vulnerable (open)
    """
    paginator = CustomPaginator()
    result = {
        "status": True, "code": 404, "next": None, "previous": None, "count": 0, "iTotalRecords": 0, "iTotalDisplayRecords": 0, "results": []
    }
    try:
        obj = Finding.objects.get(id=findingid)
    except Finding.DoesNotExist:
        return JsonResponse(result)
    try:
        # only still open
        objs = Finding.objects.filter(service=obj.service, port=obj.port, severity=obj.severity, short=obj.short, description=obj.description, status=0)
    except Exception as error:
        print(error)
        return JsonResponse(result)
    hosts = paginator.paginate_queryset(objs, request)
    serializer = FindingHostsSerializer(instance=hosts, many=True)
    return paginator.get_paginated_response(serializer.data)


@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def get_finding_details(request, findingid, format=None):
    """Get Details of a specific finding
    """
    result = {"status": True, "code": 404, "results": []}
    try:
        obj = Finding.objects.get(id=findingid)
    except Finding.DoesNotExist:
        return JsonResponse(result)
    result['code'] = 200
    serializer = FindingDetailsSerializer(instance=[obj], many=True)
    result['results'] = serializer.data
    return JsonResponse(result)

### HOST API ###

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_host_findings_severity(request, hostid, severity, format=None):
    """List all open Findings for given Host with given Severity
    """
    paginator = CustomPaginator()
    if request.query_params:
        if 'search[value]' in request.query_params:
            search_value = request.query_params['search[value]']
        else:
            search_value = None
    else:
        search_value = None
    ### create queryset
    queryset = Finding.objects.filter(host_id=hostid, status=0, severity=severity)
    ### filter by search value
    if search_value and len(search_value)>1:
        queryset = queryset.filter(
            Q(name__istartswith=search_value)|
            Q(source__istartswith=search_value)|
            Q(service__istartswith=search_value)|
            Q(cve__istartswith=search_value)|
            Q(severity__startswith=search_value)|
            Q(status__istartswith=search_value)|
            Q(short__istartswith=search_value)
        )
    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='last_seen',
                                                         default_direction='-')
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    hosts = paginator.paginate_queryset(queryset, request)
    serializer = FindingSerializer(instance=hosts, many=True)
    return paginator.get_paginated_response(serializer.data)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_host_findings_status(request, hostid, status, format=None):
    """List all open Findings for given Host with given Status
    """
    paginator = CustomPaginator()
    if request.query_params:
        if 'search[value]' in request.query_params:
            search_value = request.query_params['search[value]']
        else:
            search_value = None
    else:
        search_value = None
    ### create queryset
    queryset = Finding.objects.filter(host_id=hostid, status=status)
    ### filter by search value
    if search_value and len(search_value)>1:
        queryset = queryset.filter(
            Q(name__istartswith=search_value)|
            Q(source__istartswith=search_value)|
            Q(service__istartswith=search_value)|
            Q(cve__istartswith=search_value)|
            Q(severity__startswith=search_value)|
            Q(status__istartswith=search_value)|
            Q(short__istartswith=search_value)
        )
    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='last_seen',
                                                         default_direction='-')
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    hosts = paginator.paginate_queryset(queryset, request)
    serializer = FindingSerializer(instance=hosts, many=True)
    return paginator.get_paginated_response(serializer.data)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_host_findings(request, hostid, format=None):
    """List all open Findings for given Host
    """
    paginator = CustomPaginator()
    if request.query_params:
        if 'search[value]' in request.query_params:
            search_value = request.query_params['search[value]']
        else:
            search_value = None
    else:
        search_value = None
    ### create queryset
    queryset = Finding.objects.filter(host_id=hostid, status=0)
    ### filter by search value
    if search_value and len(search_value)>1:
        queryset = queryset.filter(
            Q(name__istartswith=search_value)|
            Q(source__istartswith=search_value)|
            Q(service__istartswith=search_value)|
            Q(cve__istartswith=search_value)|
            Q(severity__startswith=search_value)|
            Q(status__istartswith=search_value)|
            Q(short__istartswith=search_value)
        )
    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='last_seen',
                                                         default_direction='-')
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    hosts = paginator.paginate_queryset(queryset, request)
    serializer = FindingSerializer(instance=hosts, many=True)
    return paginator.get_paginated_response(serializer.data)

### FINDINGS API ###

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_findings_status(request, status, format=None):
    """List all Findings with given Status (exclude informational issues)
    """
    paginator = CustomPaginator()
    if request.query_params:
        if 'search[value]' in request.query_params:
            search_value = request.query_params['search[value]']
        else:
            search_value = None
    else:
        search_value = None
    ### create queryset
    queryset = Finding.objects.filter(~Q(severity=0), status=status)
    ### filter by search value
    if search_value and len(search_value)>1:
        queryset = queryset.filter(
            Q(name__istartswith=search_value)|
            Q(source__istartswith=search_value)|
            Q(service__istartswith=search_value)|
            Q(cve__istartswith=search_value)|
            Q(severity__startswith=search_value)|
            Q(status__istartswith=search_value)|
            Q(short__istartswith=search_value)
        )
    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='last_seen',
                                                         default_direction='-')
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    hosts = paginator.paginate_queryset(queryset, request)
    serializer = FindingSerializer(instance=hosts, many=True)
    return paginator.get_paginated_response(serializer.data)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_findings_severity(request, severity, format=None):
    """List all Findings with given Severity
    """
    paginator = CustomPaginator()
    if request.query_params:
        if 'search[value]' in request.query_params:
            search_value = request.query_params['search[value]']
        else:
            search_value = None
    else:
        search_value = None
    ### create queryset
    queryset = Finding.objects.filter(severity=severity)
    ### filter by search value
    if search_value and len(search_value)>1:
        queryset = queryset.filter(
            Q(name__istartswith=search_value)|
            Q(source__istartswith=search_value)|
            Q(service__istartswith=search_value)|
            Q(cve__istartswith=search_value)|
            Q(severity__startswith=search_value)|
            Q(status__istartswith=search_value)|
            Q(short__istartswith=search_value)
        )
    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='last_seen',
                                                         default_direction='-')
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    hosts = paginator.paginate_queryset(queryset, request)
    serializer = FindingSerializer(instance=hosts, many=True)
    return paginator.get_paginated_response(serializer.data)



@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_findings(request, format=None):
    """List all Findings
    """
    paginator = CustomPaginator()
    if request.query_params:
        if 'search[value]' in request.query_params:
            search_value = request.query_params['search[value]']
        else:
            search_value = None
    else:
        search_value = None
    ### create queryset
    queryset = Finding.objects.all()
    ### filter by search value
    if search_value and len(search_value)>1:
        queryset = queryset.filter(
            Q(name__istartswith=search_value)|
            Q(source__istartswith=search_value)|
            Q(service__istartswith=search_value)|
            Q(cve__istartswith=search_value)|
            Q(severity__startswith=search_value)|
            Q(status__istartswith=search_value)|
            Q(short__istartswith=search_value)
        )
    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='last_seen',
                                                         default_direction='-')
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    hosts = paginator.paginate_queryset(queryset, request)
    serializer = FindingSerializer(instance=hosts, many=True)
    return paginator.get_paginated_response(serializer.data)

### HOST API ###

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_hosts(request, format=None):
    """List all Hosts
    """
    paginator = CustomPaginator()
    if request.query_params:
        if 'search[value]' in request.query_params:
            search_value = request.query_params['search[value]']
        else:
            search_value = None
    else:
        search_value = None
    ### create queryset
    queryset = Host.objects.all()
    ### filter by search value
    if search_value and len(search_value)>1:
        queryset = queryset.filter(
            Q(name__istartswith=search_value)|
            Q(fqdn__istartswith=search_value)|
            Q(netbios_name__istartswith=search_value)|
            Q(ip__startswith=search_value)
        )
    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='last_scan',
                                                         default_direction='-')
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    hosts = paginator.paginate_queryset(queryset, request)
    serializer = HostSerializer(instance=hosts, many=True)
    return paginator.get_paginated_response(serializer.data)

