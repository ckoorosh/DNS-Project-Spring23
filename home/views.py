from django.shortcuts import render
from django.urls import path
from home import views
from .models import User


def get_user(request):
    if 'user-id' in request.headers:
        user_id = int(request.headers['user-id'])
        if user_id:
            return User.objects.get(id=user_id)

    return request.user

def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = User.objects.get(username=username)

        if user.password == password:
            return render(request, 'home/home.html', {'user': user})

    return render(request, 'home/login.html')
