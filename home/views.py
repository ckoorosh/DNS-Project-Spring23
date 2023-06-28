from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse

from MessangerServer.utlis import JwtUtil
from .models import User
import hashlib
import json


@csrf_exempt
def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        # maybe use login() function from django.contrib.auth instead of this
        try:
            user = User.objects.get(username=username)
            password = hashlib.sha256(password.encode() + user.salt.encode()).hexdigest()
            if user.password == password:
                token = JwtUtil().jwt_encode({'username': username})
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
            token = JwtUtil().jwt_encode({'username': username})
            response = json.dumps({'token': token})
            return HttpResponse(content=response, content_type='application/json', status=201)

    return HttpResponse("User already exists.", status=409)


@csrf_exempt
def logout(request):
    if request.method == 'POST':
        return HttpResponse("Logged out.", status=200)

    return HttpResponse("Invalid logout request.", status=400)


@csrf_exempt
def send_message(request):
    if request.method == 'POST':
        token = request.POST['token']
        message = request.POST['message']
        recipient = request.POST['recipient']
        sender = JwtUtil().jwt_decode(token)['username']

        try:
            recipient = User.objects.get(username=recipient)
            sender = User.objects.get(username=sender)
        except User.DoesNotExist:
            return HttpResponse("Invalid recipient.", status=400)

        if recipient == sender:
            return HttpResponse("Cannot send message to self.", status=400)
        
        # todo send message to recipient
        
        return HttpResponse("Message sent.", status=200)
    
    return HttpResponse("Invalid message request.", status=400)