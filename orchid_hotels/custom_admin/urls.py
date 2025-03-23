from django.urls import path
from .views import admin_login, admin_dashboard, admin_logout

urlpatterns = [
    path('login/', admin_login, name='admin_login'),
    path('dashboard/', admin_dashboard, name='admin_dashboard'),
    path('logout/', admin_logout, name='admin_logout'),
]
