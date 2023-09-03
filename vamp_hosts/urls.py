
from django.urls import path

from vamp_hosts import views

urlpatterns = [
    # All files
    path('', views.list_hosts, name='list_hosts'),
    path('<int:hostid>/view/', views.view_host, name='view_host'),
    path('<int:hostid>/add/tag/', views.host_add_tag, name='host_add_tag'),
    path('<slug:hostid>/finding/<slug:findingid>/<str:operation>/', views.view_ops_finding, name='view_ops_finding'),
    path('<slug:hostid>/finding/<slug:findingid>/reset/exception/', views.reset_exception_request, name='reset_exception_request'),
    path('<slug:hostid>/finding/<slug:findingid>/reset/ignore/', views.reset_ignore_request, name='reset_ignore_request'),
]
