# users/views.py
from django.contrib import messages
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from models import Reservation
from django.utils import timezone

def register(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        name = request.POST['name']
        lastname = request.POST['lastname']
        email = request.POST['email']
        
    
        if User.objects.filter(username=username).exists():
            messages.error(request, "This username is already taken. Please choose a different one.")
            return redirect('register')
        
        user = User.objects.create_user(username, email, password)
        user.first_name = name
        user.last_name = lastname
        user.save()
        return redirect('login')
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

    
    