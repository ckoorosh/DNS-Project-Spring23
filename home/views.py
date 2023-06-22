from django.shortcuts import render
from django.urls import path
from home import views
from models import User, ChatMessage


def get_user(request):
    if 'user-id' in request.headers:
        user_id = int(request.headers['user-id'])
        if user_id:
            return User.objects.get(id=user_id)

    return request.user
