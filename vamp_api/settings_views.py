
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

### STATISTICS API ###

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def top_findings_by_asset(request, format=None):
    """List Top 10 Findings with most affected assets
    """
    result = {
        "status": True, "code": 200, "next": None, "previous": None, "count": 10, "iTotalRecords": 10, "iTotalDisplayRecords": 10, "results": []
    }
    queryset = Finding.objects.filter(status=0, severity__gte=1).values('short', 'severity', 'exploited_in_the_wild', 'id')
    queryset = queryset.annotate(assets=Count('short')).order_by('-assets', '-severity', '-exploited_in_the_wild')[:10]
    serializer = TopFindingSerializer(instance=queryset, many=True)
    result['results'] = serializer.data
    return JsonResponse(result)


@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def top_vulnerable_hosts(request, format=None):
    """List Top 10 Hosts with most critical open findings
    """
    result = {
        "status": True, "code": 200, "next": None, "previous": None, "count": 10, "iTotalRecords": 10, "iTotalDisplayRecords": 10, "results": []
    }
    queryset = Host.objects.annotate(vuln_crit=Count('finding', filter=Q(finding__severity=4)&Q(finding__status=0)))
    queryset =     queryset.annotate(vuln_high=Count('finding', filter=Q(finding__severity=3)&Q(finding__status=0)))
    queryset =     queryset.annotate(vuln_med=Count('finding', filter=Q(finding__severity=2)&Q(finding__status=0)))
    queryset =     queryset.annotate(vuln_low=Count('finding', filter=Q(finding__severity=1)&Q(finding__status=0)))
    queryset = queryset.order_by('-vuln_crit','-vuln_high','-vuln_med','-vuln_low')[:10]
    serializer = VulnHostSerializer(instance=queryset, many=True)
    result['results'] = serializer.data
    response = JsonResponse(result)
    return response

### SETTINGS API ###

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_tenable_endpoints(request, format=None):
    """List all Tenable API configurations
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
    queryset = TenableAPI.objects.all()
    ### filter by search value
    if search_value and len(search_value)>1:
        queryset = queryset.filter(
            Q(server__istartswith=search_value)|
            Q(severities__istartswith=search_value)
        )
    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='id',
                                                         default_direction='-')
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    hosts = paginator.paginate_queryset(queryset, request)
    serializer = TenableAPISerializer(instance=hosts, many=True)
    return paginator.get_paginated_response(serializer.data)

