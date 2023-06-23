from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.shortcuts import render
from django.urls import path
from .models import User
from .utils import *
import hashlib
import json


@csrf_exempt
def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        try:
            user = User.objects.get(username=username)
            password = hashlib.sha256(password.encode() + user.salt.encode()).hexdigest()
            if user.password == password:
                token = jwt_encode({'username': username})
                response = json.dumps({'token': token})
                return HttpResponse(content=response, content_type='application/json', status=200)
        except User.DoesNotExist:
            return HttpResponse("Invalid login credentials.", status=401)

    return HttpResponse("Invalid login credentials.", status=401)


@csrf_exempt
def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        public_key = request.POST['public_key']

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = User(username=username, public_key=public_key)
            user.set_password(password)
            user.set_pk_identifier()
            user.save()
            token = jwt_encode({'username': username})
            response = json.dumps({'token': token})
            return HttpResponse(content=response, content_type='application/json', status=201)

    return HttpResponse("User already exists.", status=409)
