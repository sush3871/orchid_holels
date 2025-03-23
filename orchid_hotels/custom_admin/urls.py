from django.urls import path
from .views import admin_login, admin_dashboard, admin_logout, admin_signup, password_reset, password_reset_confirm

urlpatterns = [
    path('', admin_login, name='admin_login'),  # Default redirects to login
    path('sign-in/', admin_login, name='admin_login'),
    path('dashboard/', admin_dashboard, name='admin_dashboard'),
    path('logout/', admin_logout, name='admin_logout'),
    path('sign-up/', admin_signup, name='admin_signup'),
    path('forgot-password/', password_reset, name='password_reset'),
    path('password_reset_confirm/<uidb64>/<token>/', password_reset_confirm, name='password_reset_confirm'),

]
