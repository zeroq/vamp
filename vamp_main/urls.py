"""vamp URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.contrib import admin
from django.urls import path, include

from vamp_main import views

urlpatterns = [
    path('', views.home, name='home'),
    path('accounts/', include(('vamp_accounts.urls', 'accounts'), namespace='accounts')),
    path('hosts/', include(('vamp_hosts.urls', 'hosts'), namespace='hosts')),
    path('findings/', include(('vamp_findings.urls', 'findings'), namespace='findings')),
    path('api-auth/', include('rest_framework.urls')),
    path('api/', include(('vamp_api.urls', 'api'), namespace='api')),
    path('scans/', include(('vamp_scans.urls', 'scans'), namespace='scans')),
    path('exceptions/', include(('vamp_exceptions.urls', 'exceptions'), namespace='exceptions')),
]

if settings.ADMIN_ENABLED:
    urlpatterns = [
        path('admin/', admin.site.urls),
    ] + urlpatterns
