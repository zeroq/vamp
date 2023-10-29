
from django.urls import path

from vamp_findings import views

urlpatterns = [
    # All files
    path('', views.list_findings, name='list_findings'),
    path('<int:findingid>/view/', views.view_finding, name='view_finding'),
    path('<int:status>/status/', views.list_findings_status, name='list_findings_status'),
    path('<int:severity>/severity/', views.list_findings_severity, name='list_findings_severity'),
    path('<int:findingid>/change/<str:status>/', views.change_finding_affected_hosts, name='change_finding_affected_hosts'),
    path('<int:findingid>/single/change/<str:status>/', views.change_finding_for_host, name='change_finding_for_host'),
]
