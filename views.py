# users/views.py
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.utils import timezone
from models import Reservation

def register(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.email = request.POST.get('email', '').strip()
            user.first_name = request.POST.get('name', '').strip()
            user.last_name = request.POST.get('lastname', '').strip()
            
            if User.objects.filter(email=user.email).exists():
                messages.error(request, "An account with this email already exists.")
                return redirect('register')
            
            user.save()
            messages.success(request, "Registration successful! You can now log in.")
            return redirect('login')
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = UserCreationForm()

    return render(request, 'users/register.html', {'form': form})


def login_view(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            messages.success(request, f"Welcome back, {user.first_name or user.username}!")
            return redirect('profile')
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()

    return render(request, 'users/login.html', {'form': form})


def logout_view(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('login')

@login_required
def profile_view(request):
    user = request.user
    now = timezone.now()
    
    current_reservations = Reservation.objects.filter(user=user, end_time__gte=now)
    past_reservations = Reservation.objects.filter(user=user, end_time__lt=now)

    return render(request, 'users/profile.html', {
        'user': user,
        'current_reservations': current_reservations,
        'past_reservations': past_reservations
    })
