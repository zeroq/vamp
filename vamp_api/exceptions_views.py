
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

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_open_exceptions(request, format=None):
    """List all open exception requests
    """
    paginator = CustomPaginator()
    queryset = Exceptions.objects.filter(approved=False)
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='last_update',
                                                         default_direction='-')
    if order_by_column:
        queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    exceptions = paginator.paginate_queryset(queryset, request)
    serializer = ExceptionSerializer(instance=exceptions, many=True)
    return paginator.get_paginated_response(serializer.data)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_granted_exceptions(request, format=None):
    """List all granted and still valid exception requests
    """
    paginator = CustomPaginator()
    queryset = Exceptions.objects.filter(approved=True, still_valid=True)
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='last_update',
                                                         default_direction='-')
    if order_by_column:
        queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    exceptions = paginator.paginate_queryset(queryset, request)
    serializer = ExceptionSerializer(instance=exceptions, many=True)
    return paginator.get_paginated_response(serializer.data)


@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_expired_exceptions(request, format=None):
    """List all expired exception requests
    """
    paginator = CustomPaginator()
    queryset = Exceptions.objects.filter(still_valid=False)
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='last_update',
                                                         default_direction='-')
    if order_by_column:
        queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    exceptions = paginator.paginate_queryset(queryset, request)
    serializer = ExceptionSerializer(instance=exceptions, many=True)
    return paginator.get_paginated_response(serializer.data)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_exceptions_host(request, hostid, format=None):
    """List all granted and still valid exception requests for given host
    """
    paginator = CustomPaginator()
    queryset = Exceptions.objects.filter(approved=True, still_valid=True, host__id=hostid)
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='last_update',
                                                         default_direction='-')
    if order_by_column:
        queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    exceptions = paginator.paginate_queryset(queryset, request)
    serializer = ExceptionSerializer(instance=exceptions, many=True)
    return paginator.get_paginated_response(serializer.data)
