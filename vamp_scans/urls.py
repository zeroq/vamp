from django.urls import path

from vamp_scans import views

urlpatterns = [
    # All files
    path('import/nessus/', views.import_nessus, name='import_nessus'),
    path('configure/tenable/', views.configure_tenable_api, name='configure_tenable_api'),
    path('delete/tenable/<int:tid>/', views.delete_tenable_api, name='delete_tenable_api'),
    #path('<int:findingid>/view/', views.view_finding, name='view_finding'),
    #path('<int:status>/status/', views.list_findings_status, name='list_findings_status'),
    #path('<int:severity>/severity/', views.list_findings_severity, name='list_findings_severity'),
    #path('<int:findingid>/change/<str:status>/', views.change_finding_affected_hosts, name='change_finding_affected_hosts'),
]
