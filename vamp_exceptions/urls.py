
from django.urls import path

from vamp_exceptions import views

urlpatterns = [
    # All files
    path('', views.list_exceptions, name='list_exceptions'),
    path('granted/', views.list_granted_exceptions, name='list_granted_exceptions'),
    path('expired/', views.list_expired_exceptions, name='list_expired_exceptions'),
    path('<int:exceptionid>/reject/', views.reject_request, name='reject_request'),
    path('<int:exceptionid>/grant/', views.grant_request, name='grant_request'),
    path('<int:hostid>/add/request/', views.add_request, name='add_request'),
    # Ignore Requests
    path('ignore/requests/', views.list_ignore_requests, name='list_ignore_requests'),
    path('ignore/granted/', views.list_granted_ignore, name='list_granted_ignore'),
    path('ignore/<int:ignoreid>/grant/', views.grant_ignore_request, name='grant_ignore_request'),
    path('ignore/<int:ignoreid>/reject/', views.reject_ignore_request, name='reject_ignore_request'),
    path('ignore/<int:hostid>/add/request/',views.add_ignore_request, name='add_ignore_request'),
    #path('<slug:hostid>/finding/<slug:findingid>/<str:operation>/', views.view_ops_finding, name='view_ops_finding'),
]
