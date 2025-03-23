from django.urls import path
from .views import admin_login, admin_dashboard, admin_logout, admin_signup

urlpatterns = [
    path('login/', admin_login, name='admin_login'),
    path('dashboard/', admin_dashboard, name='admin_dashboard'),
    path('logout/', admin_logout, name='admin_logout'),
    path('sign-up/', admin_signup, name='admin_signup'),
]
