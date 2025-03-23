from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required

def admin_login(request):
    if request.user.is_authenticated:
        return redirect('admin_dashboard')  # Redirect if already logged in
    
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None and user.is_staff:
            login(request, user)
            return redirect('admin_dashboard')
        else:
            return render(request, 'custom_admin/login.html', {'error': 'Invalid credentials'})
    
    return render(request, 'custom_admin/login.html')

@login_required(login_url='/custom-admin/login/')

def admin_dashboard(request):
    return render(request, 'custom_admin/dashboard.html')

def admin_logout(request):
    logout(request)
    return redirect('admin_login')

def admin_signup(request):
    return render(request, 'custom_admin/sign-up.html')
