
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
    #path('<slug:hostid>/finding/<slug:findingid>/<str:operation>/', views.view_ops_finding, name='view_ops_finding'),
]
