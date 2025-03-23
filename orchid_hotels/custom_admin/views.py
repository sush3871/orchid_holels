from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.decorators import login_required

# For Password Reset
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.forms import SetPasswordForm
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.contrib.auth.forms import PasswordResetForm
from .forms import CustomPasswordResetForm 


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
            return redirect('admin_dashboard')  # Send user to dashboard
        else:
            messages.error(request, 'Invalid username or password. Please try again.')

    return render(request, 'custom_admin/sign-in.html')

@login_required(login_url='/custom-admin/sign-in/')
def admin_dashboard(request):
    if not request.user.is_staff:
        messages.error(request, 'You do not have permission to access this page.')
        return redirect('admin_login')
    
    return render(request, 'custom_admin/dashboard.html')

def admin_logout(request):
    logout(request)
    messages.warning(request, 'Please login to proceed.')  # Logout message
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

# Password reset view
def password_reset(request):
    if request.method == 'POST':
        form = CustomPasswordResetForm(request.POST)  # Use CustomPasswordResetForm
        
        if form.is_valid():
            email = form.cleaned_data['email']
            
            # Check if the email exists in the database
            try:
                user = get_user_model().objects.get(email=email)
            except get_user_model().DoesNotExist:
                messages.error(request, 'Email does not exist.')
                return redirect('password_reset')

            # Generate password reset token
            token = default_token_generator.make_token(user)
            
            # Encode the user ID
            uid = urlsafe_base64_encode(str(user.pk).encode())

            # Create the reset link
            reset_link = request.build_absolute_uri(f"/password_reset_confirm/{uid}/{token}/")
            
            # Prepare the reset email
            subject = "Password Reset Request"
            message = f"Click the link to reset your password: {reset_link}"
            send_mail(subject, message, 'sushshirke96@gmail.com', [email])

            messages.success(request, 'Password reset email sent.')
            return redirect('password_reset')  # Redirect after sending the email
    else:
        form = CustomPasswordResetForm()  # Use CustomPasswordResetForm

    return render(request, 'custom_admin/password-reset.html', {'form': form})


# Password reset confirmation view
def password_reset_confirm(request, uidb64, token):
    try:
        # Decode the uid from the URL
        uid = urlsafe_base64_decode(uidb64).decode()
        user = get_user_model().objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, user.DoesNotExist):
        user = None

    # Check if the user exists and if the token is valid
    if user and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(user, request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, 'Your password has been reset successfully.')
                return redirect('admin_login')  # Redirect to login page
        else:
            form = SetPasswordForm(user)
        
        return render(request, 'custom_admin/password-reset-confirm.html', {'form': form})
    else:
        messages.error(request, 'The password reset link is invalid or has expired.')
        return redirect('password_reset')  # Redirect to the password reset page