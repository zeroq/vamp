
from django.urls import path
from vamp_accounts import views

urlpatterns = [
    path('logout/', views.accounts_logout, name='logout'),
    path('login/', views.accounts_login, name='login'),
]
