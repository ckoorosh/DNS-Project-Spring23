from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse

from MessangerServer.utlis import JwtUtil
from .models import *
import hashlib
import json
from MessangerServer.websocket_manager import WebsocketManager


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
        name = request.POST['name']
        username = request.POST['username']
        password = request.POST['password']
        public_key = request.POST.get('public_key', None)

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = User(username=username, public_key=public_key, name=name)
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
def view_online_users(request):
    if request.method == 'POST':
        token = request.headers['Authorization'].split(' ')[1]
        username = JwtUtil().jwt_decode(token)['username']
        try:
            user = User.objects.get(username=username)
            online_users = WebsocketManager().get_connected_user_ids()
            online_users.remove(user.id)
            response = []
            for online_user in online_users:
                user_data = {'username': User.objects.get(id=online_user).username,
                             'name': User.objects.get(id=online_user).name
                            }
                response.append(user_data)
            response = json.dumps(response)
            return HttpResponse(content=response, content_type='application/json', status=200)
        except User.DoesNotExist:
            return HttpResponse("Invalid user.", status=400)

    return HttpResponse("Invalid online users request.", status=400)


@csrf_exempt
def send_chat_message(request):
    if request.method == 'POST':
        token = request.headers['Authorization'].split(' ')[1]
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
        
        success = WebsocketManager().send_message(recipient.id, message)
        if success:
            return HttpResponse("Message sent.", status=200)
        else:
            return HttpResponse("Message not sent.", status=400)
            
    return HttpResponse("Invalid message request.", status=400)


@csrf_exempt
def send_group_message(request):
    if request.method == 'POST':
        token = request.headers['Authorization'].split(' ')[1]
        message = request.POST['message']
        group = request.POST['group']
        sender = JwtUtil().jwt_decode(token)['username']

        try:
            sender = User.objects.get(username=sender)
            group = GroupChat.objects.get(identifier=group)
            group_chat_users = GroupChatUser.objects.filter(group=group)
        except (GroupChat.DoesNotExist, User.DoesNotExist):
            return HttpResponse("Invalid group or user.", status=400)

        for group_user in group_chat_users:
            if group_user.user == sender:
                continue
            WebsocketManager().send_message_to_user(group_user.id, message)

    return HttpResponse("Invalid message request.", status=400)


@csrf_exempt
def create_group(request):
    if request.method == 'POST':
        token = request.headers['Authorization'].split(' ')[1]
        group_name = request.POST['name']

        try:
            creator = User.objects.get(username=JwtUtil().jwt_decode(token)['username'])
        except User.DoesNotExist:
            return HttpResponse("Invalid group request.", status=400)

        group = GroupChat(name=group_name)
        group.set_identifier()
        group.save()
        group_user = GroupChatUser(user=creator, group=group, role='admin')
        group_user.save()
        return HttpResponse("Group created.", status=201)

    return HttpResponse("Invalid group request.", status=400)


@csrf_exempt
def show_group_chats(request):
    if request.method == 'POST':
        token = request.headers['Authorization'].split(' ')[1]
        username = JwtUtil().jwt_decode(token)['username']

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return HttpResponse("Invalid group request.", status=400)

        group_chats = GroupChatUser.objects.filter(user=user)
        response = []
        for group_chat in group_chats:
            response.append({'name': group_chat.group.name, 'id': group_chat.group.identifier})

        return HttpResponse(json.dumps(response), status=200)

    return HttpResponse("Invalid group request.", status=400)


@csrf_exempt
def add_member_to_group(request):
    if request.method == 'POST':
        token = request.headers['Authorization'].split(' ')[1]
        username = JwtUtil().jwt_decode(token)['username']
        group = request.POST['group']
        member = request.POST['user']

        try:
            user = User.objects.get(username=username)
            group = GroupChat.objects.get(identifier=group)
            group_user = GroupChatUser.objects.get(user=user, group=group)
            member = User.objects.get(username=member)
        except (User.DoesNotExist, GroupChat.DoesNotExist):
            return HttpResponse("Invalid group request.", status=400)
        
        if group_user.role != 'admin':
            return HttpResponse("User is not admin.", status=400)
        
        if not WebsocketManager().is_user_online(member.id):
            return HttpResponse("User is not online.", status=400)

        if GroupChatUser.objects.filter(user=member, group=group).exists():
            return HttpResponse("User already in group.", status=400)

        group_user = GroupChatUser(user=member, group=group, role='member')
        group_user.save()
        return HttpResponse("User added to group.", status=200)

    return HttpResponse("Invalid group request.", status=400)


@csrf_exempt
def remove_member_from_group(request):
    if request.method == 'POST':
        token = request.headers['Authorization'].split(' ')[1]
        username = JwtUtil().jwt_decode(token)['username']
        group = request.POST['group']
        member = request.POST['user']

        try:
            user = User.objects.get(username=username)
            group = GroupChat.objects.get(identifier=group)
            group_user = GroupChatUser.objects.get(user=user, group=group)
            member = User.objects.get(username=member)
        except (User.DoesNotExist, GroupChat.DoesNotExist):
            return HttpResponse("Invalid group request.", status=400)

        if group_user.role != 'admin':
            return HttpResponse("User is not admin.", status=400)

        if not GroupChatUser.objects.filter(user=member, group=group).exists():
            return HttpResponse("User not in group.", status=400)

        group_user = GroupChatUser.objects.get(user=member, group=group)
        group_user.delete()
        return HttpResponse("User removed from group.", status=200)

    return HttpResponse("Invalid group request.", status=400)


@csrf_exempt
def make_member_admin(request):
    if request.method == 'POST':
        token = request.headers['Authorization'].split(' ')[1]
        username = JwtUtil().jwt_decode(token)['username']
        group = request.POST['group']
        member = request.POST['user']

        try:
            user = User.objects.get(username=username)
            group = GroupChat.objects.get(identifier=group)
            group_user = GroupChatUser.objects.get(user=user, group=group)
            member = User.objects.get(username=member)
        except (User.DoesNotExist, GroupChat.DoesNotExist):
            return HttpResponse("Invalid group request.", status=400)

        if group_user.role != 'admin':
            return HttpResponse("User is not admin.", status=400)

        if not GroupChatUser.objects.filter(user=member, group=group).exists():
            return HttpResponse("Member not in group.", status=400)

        group_user = GroupChatUser.objects.get(user=member, group=group)
        group_user.role = 'admin'
        group_user.save()
        return HttpResponse("Member made admin.", status=200)

    return HttpResponse("Invalid group request.", status=400)