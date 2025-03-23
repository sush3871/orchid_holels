from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.decorators import login_required

def admin_login(request):
    if request.user.is_authenticated:
        logout(request)  # Force logout if already logged in
        return redirect('admin_login')

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None and user.is_staff:
            login(request, user)
            messages.success(request, 'Login successful! Redirecting...')
            return redirect('admin_dashboard')  # Send user to dashboard
        else:
            messages.error(request, 'Invalid username or password. Please try again.')

    return render(request, 'custom_admin/login.html')  # Return login page if not logged in

@login_required(login_url='/custom-admin/sign-in/')
def admin_dashboard(request):
    if not request.user.is_staff:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('admin_login')
    
    return render(request, 'custom_admin/dashboard.html')

def admin_logout(request):
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('admin_login')
@login_required(login_url='/custom-admin/sign-in/')  
def admin_dashboard(request):
    if not request.user.is_staff:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('admin_login')
    
    return render(request, 'custom_admin/dashboard.html')

def admin_logout(request):
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('admin_login')

def admin_signup(request):
    if request.method == 'POST':
        username = request.POST.get('username').strip()
        email = request.POST.get('email').strip()
        password = request.POST.get('password').strip()
        confirm_password = request.POST.get('confirm_password').strip()

        # Check if all fields are filled
        if not username or not email or not password or not confirm_password:
            messages.error(request, 'All fields are required.')
            return redirect('admin_signup')

        # Password match validation
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return redirect('admin_signup')

        # Username and Email uniqueness validation
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
            return redirect('admin_signup')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email is already registered.')
            return redirect('admin_signup')

        # Create and save the user
        user = User.objects.create_user(username=username, email=email, password=password)
        user.is_staff = True
        user.save()

        messages.success(request, 'Admin account created successfully. Please sign in.')
        return redirect('admin_login')

    return render(request, 'custom_admin/sign-up.html')
