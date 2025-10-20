# users/views.py
from django.contrib import messages
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from models import Reservation
from django.utils import timezone
from django.core.exceptions import ValidationError


def create_user_account(username, email, password, first_name, last_name):
    """Pagalbinė funkcija vartotojo sukūrimui su patikrinimu."""
    if User.objects.filter(username=username).exists():
        raise ValidationError("This username is already taken.")
    
    user = User.objects.create_user(username=username, email=email, password=password)
    user.first_name = first_name
    user.last_name = last_name
    user.save()
    return user

def register(request):
    """Naudotojo registracijos peržiūra su loginės logikos atskyrimu."""
    if request.method == "POST":
        data = request.POST
        try:
            user = create_user_account(
                username=data.get('username'),
                email=data.get('email'),
                password=data.get('password'),
                first_name=data.get('name'),
                last_name=data.get('lastname'),
            )
            messages.success(request, f"Account created for {user.username}! You can now log in.")
            return redirect('login')

        except ValidationError as e:
            messages.error(request, str(e))
            return redirect('register')
        except Exception:
            messages.error(request, "Unexpected error occurred during registration.")
            return redirect('register')

    return render(request, 'users/register.html')

def login_view(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, "You have successfully logged in!")
            return redirect('profile')  # Redirect to the profile view
        else:
            messages.error(request, "Bad credentials!")
    
    return render(request, 'users/login.html')



def logout_view(request):
    logout(request)
    messages.success(request, "Logged out successfully!")
    return redirect('login')

@login_required
def profile_view(request):
    user = request.user
    current_reservations = Reservation.objects.filter(user=user, end_time__gte=timezone.now()).using('default')
    past_reservations = Reservation.objects.filter(user=user, end_time__lt=timezone.now()).using('default')

    return render(request, 'users/profile.html', {
        'user': user,
        'current_reservations': current_reservations,
        'past_reservations': past_reservations
    })

    
    