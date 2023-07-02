import asyncio
import json

from django.views.decorators.csrf import csrf_exempt

from MessangerServer.utlis import JwtUtil
from MessangerServer.websocket_manager import WebsocketManager
from security.Session import SessionHandler
from .models import *


@csrf_exempt
def login(request):
    session_handler = SessionHandler()
    session_id = _get_session_id(request)
    headers, body = session_handler.decrypt_message(session_id, request.POST['nonce'], request.POST['message'])
    if request.method == 'POST':
        username = body['username']
        password = body['password']

        # maybe use login() function from django.contrib.auth instead of this
        try:
            user = User.objects.get(username=username)
            password = hashlib.sha256(password.encode() + user.salt.encode()).hexdigest()
            if user.password == password:
                token = JwtUtil().jwt_encode({'username': username})
                response = json.dumps({'token': token})
                return session_handler.get_http_response(session_id, content=response, content_type='application/json',
                                                         status=200)
        except User.DoesNotExist:
            return session_handler.get_http_response(session_id, "Invalid login credentials.", status=401)

    return session_handler.get_http_response(session_id, "Invalid login credentials.", status=401)


@csrf_exempt
def register(request):
    session_handler = SessionHandler()
    session_id = _get_session_id(request)
    headers, body = session_handler.decrypt_message(session_id, request.POST['nonce'], request.POST['message'])
    if request.method == 'POST':
        SessionHandler()
        name = body['name']
        username = body['username']
        password = body['password']

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = User(username=username, name=name)
            user.set_password(password)
            user.set_pk_identifier()
            user.save()
            token = JwtUtil().jwt_encode({'username': username})
            response = json.dumps({'token': token})
            return session_handler.get_http_response(session_id, content=response, content_type='application/json',
                                                     status=201)

    return session_handler.get_http_response(session_id, "User already exists.", status=409)


@csrf_exempt
def logout(request):
    session_handler = SessionHandler()
    session_id = _get_session_id(request)
    headers, body = session_handler.decrypt_message(session_id, request.POST['nonce'], request.POST['message'])
    if request.method == 'POST':
        return session_handler.get_http_response(session_id, "Logged out.", status=200)

    return session_handler.get_http_response(session_id, "Invalid logout request.", status=400)


@csrf_exempt
def send_public_keys(request):
    session_handler = SessionHandler()
    session_id = _get_session_id(request)
    headers, body = session_handler.decrypt_message(session_id, request.POST['nonce'], request.POST['message'])
    if request.method == 'POST':
        token = headers['Authorization'].split(' ')[1]
        username = JwtUtil().jwt_decode(token)['username']
        idk = body['idk']
        signed_prekey = body['signed_prekey']
        prekey_signature = body['prekey_signature']
        ot_prekeys = body['ot_prekeys']
        try:
            user = User.objects.get(username=username)
            user.idk = idk
            user.signed_prekey = signed_prekey
            user.prekey_signature = prekey_signature
            user.save()
            for index, ot_prekey in ot_prekeys.items():
                user_ot_prekey = OTPreKey(user=user, index=index, key=ot_prekey)
                user_ot_prekey.save()
            return session_handler.get_http_response(session_id, "Public key updated.", status=200)
        except User.DoesNotExist:
            return session_handler.get_http_response(session_id, "Invalid user.", status=400)

    return session_handler.get_http_response(session_id, "Invalid public key request.", status=400)


def get_otprekeys(user):
    otprekeys = OTPreKey.objects.filter(user=user)
    otprekeys = {otprekey.index: otprekey.key for otprekey in otprekeys}
    return otprekeys


@csrf_exempt
def view_online_users(request):
    session_handler = SessionHandler()
    session_id = _get_session_id(request)
    headers, body = session_handler.decrypt_message(session_id, request.POST['nonce'], request.POST['message'])
    if request.method == 'POST':
        token = headers['Authorization'].split(' ')[1]
        username = JwtUtil().jwt_decode(token)['username']
        try:
            user = User.objects.get(username=username)
            online_users = WebsocketManager().get_connected_user_ids()
            online_users.remove(user.username)
            response = []
            for online_username in online_users:
                online_user = User.objects.get(username=online_username)
                user_data = {'username': online_user.username,
                             'name': online_user.name}
                response.append(user_data)
            response = json.dumps(response)
            return session_handler.get_http_response(session_id, content=response, content_type='application/json',
                                                     status=200)
        except User.DoesNotExist:
            return session_handler.get_http_response(session_id, "Invalid user.", status=400)

    return session_handler.get_http_response(session_id, "Invalid online users request.", status=400)


@csrf_exempt
def send_chat_message(request):
    session_handler = SessionHandler()
    session_id = _get_session_id(request)
    headers, body = session_handler.decrypt_message(session_id, request.POST['nonce'], request.POST['message'])
    if request.method == 'POST':
        token = headers['Authorization'].split(' ')[1]
        message = body['message']
        recipient = body['recipient']
        sender = JwtUtil().jwt_decode(token)['username']

        try:
            recipient = User.objects.get(username=recipient)
            sender = User.objects.get(username=sender)
        except User.DoesNotExist:
            return session_handler.get_http_response(session_id, "Invalid recipient.", status=400)

        if recipient == sender:
            return session_handler.get_http_response(session_id, "Cannot send message to self.", status=400)

        success = WebsocketManager().send_message(recipient.username, message)
        if success:
            return session_handler.get_http_response(session_id, "Message sent.", status=200)
        else:
            return session_handler.get_http_response(session_id, "Message not sent.", status=400)

    return session_handler.get_http_response(session_id, "Invalid message request.", status=400)


@csrf_exempt
def send_group_message(request):
    session_handler = SessionHandler()
    session_id = _get_session_id(request)
    headers, body = session_handler.decrypt_message(session_id, request.POST['nonce'], request.POST['message'])
    if request.method == 'POST':
        token = headers['Authorization'].split(' ')[1]
        group = body['group']
        sender = JwtUtil().jwt_decode(token)['username']

        try:
            sender = User.objects.get(username=sender)
            group = GroupChat.objects.get(identifier=group)
            group_chat_users = GroupChatUser.objects.filter(group=group)
        except (GroupChat.DoesNotExist, User.DoesNotExist):
            return session_handler.get_http_response(session_id, "Invalid group or user.", status=400)

        for group_user in group_chat_users:
            # if group_user.user == sender:
            #     continue
            if WebsocketManager().is_user_online(group_user.user.username):
                body['sender'] = sender.username
                asyncio.run(WebsocketManager().send_message_to_user(group_user.user.username, f'4{json.dumps(body)}'))

        return session_handler.get_http_response(session_id, "Ok", status=200)

    return session_handler.get_http_response(session_id, "Invalid message request.", status=400)


@csrf_exempt
def create_group(request):
    session_handler = SessionHandler()
    session_id = _get_session_id(request)
    headers, body = session_handler.decrypt_message(session_id, request.POST['nonce'], request.POST['message'])
    if request.method == 'POST':
        token = headers['Authorization'].split(' ')[1]
        group_name = body['name']

        try:
            creator = User.objects.get(username=JwtUtil().jwt_decode(token)['username'])
        except User.DoesNotExist:
            return session_handler.get_http_response(session_id, "Invalid group request.", status=400)

        group = GroupChat(name=group_name)
        group.set_identifier()
        group.save()
        group_user = GroupChatUser(user=creator, group=group, role='admin')
        group_user.save()
        return session_handler.get_http_response(session_id, group.identifier, status=201)

    return session_handler.get_http_response(session_id, "Invalid group request.", status=400)


@csrf_exempt
def show_group_chats(request):
    session_handler = SessionHandler()
    session_id = _get_session_id(request)
    headers, body = session_handler.decrypt_message(session_id, request.POST['nonce'], request.POST['message'])
    if request.method == 'POST':
        token = headers['Authorization'].split(' ')[1]
        username = JwtUtil().jwt_decode(token)['username']

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return session_handler.get_http_response(session_id, "Invalid group request.", status=400)

        group_chats = GroupChatUser.objects.filter(user=user)
        response = []
        for group_chat in group_chats:
            response.append({'name': group_chat.group.name, 'id': group_chat.group.identifier})

        return session_handler.get_http_response(session_id, json.dumps(response), status=200)

    return session_handler.get_http_response(session_id, "Invalid group request.", status=400)


@csrf_exempt
def add_member_to_group(request):
    session_handler = SessionHandler()
    session_id = _get_session_id(request)
    headers, body = session_handler.decrypt_message(session_id, request.POST['nonce'], request.POST['message'])
    if request.method == 'POST':
        token = headers['Authorization'].split(' ')[1]
        username = JwtUtil().jwt_decode(token)['username']
        group = body['group']
        member = body['user']
        try:
            user = User.objects.get(username=username)
            group = GroupChat.objects.get(identifier=group)
            group_user = GroupChatUser.objects.get(user=user, group=group)
            member = User.objects.get(username=member)
        except (User.DoesNotExist, GroupChat.DoesNotExist):
            return session_handler.get_http_response(session_id, "Invalid group request.", status=400)

        if group_user.role != 'admin':
            return session_handler.get_http_response(session_id, "User is not admin.", status=400)

        if not WebsocketManager().is_user_online(member.username):
            return session_handler.get_http_response(session_id, "User is not online.", status=400)

        if GroupChatUser.objects.filter(user=member, group=group).exists():
            return session_handler.get_http_response(session_id, "User already in group.", status=400)

        group_user = GroupChatUser(user=member, group=group, role='member')
        group_user.save()
        if WebsocketManager().is_user_online(member.username):
            body['sender'] = user.username
            asyncio.run(WebsocketManager().send_message_to_user(member.username, f'3{json.dumps(body)}'))

        return session_handler.get_http_response(session_id, "User added to group.", status=200)

    return session_handler.get_http_response(session_id, "Invalid group request.", status=400)


@csrf_exempt
def remove_member_from_group(request):
    session_handler = SessionHandler()
    session_id = _get_session_id(request)
    headers, body = session_handler.decrypt_message(session_id, request.POST['nonce'], request.POST['message'])
    if request.method == 'POST':
        token = headers['Authorization'].split(' ')[1]
        username = JwtUtil().jwt_decode(token)['username']
        group = body['group']
        member = body['user']

        try:
            user = User.objects.get(username=username)
            group = GroupChat.objects.get(identifier=group)
            group_user = GroupChatUser.objects.get(user=user, group=group)
            member = User.objects.get(username=member)
        except (User.DoesNotExist, GroupChat.DoesNotExist):
            return session_handler.get_http_response(session_id, "Invalid group request.", status=400)

        if group_user.role != 'admin':
            return session_handler.get_http_response(session_id, "User is not admin.", status=400)

        if not GroupChatUser.objects.filter(user=member, group=group).exists():
            return session_handler.get_http_response(session_id, "User not in group.", status=400)

        group_user = GroupChatUser.objects.get(user=member, group=group)
        group_user.delete()
        return session_handler.get_http_response(session_id, "User removed from group.", status=200)

    return session_handler.get_http_response(session_id, "Invalid group request.", status=400)


@csrf_exempt
def make_member_admin(request):
    session_handler = SessionHandler()
    session_id = _get_session_id(request)
    headers, body = session_handler.decrypt_message(session_id, request.POST['nonce'], request.POST['message'])
    if request.method == 'POST':
        token = headers['Authorization'].split(' ')[1]
        username = JwtUtil().jwt_decode(token)['username']
        group = body['group']
        member = body['user']

        try:
            user = User.objects.get(username=username)
            group = GroupChat.objects.get(identifier=group)
            group_user = GroupChatUser.objects.get(user=user, group=group)
            member = User.objects.get(username=member)
        except (User.DoesNotExist, GroupChat.DoesNotExist):
            return session_handler.get_http_response(session_id, "Invalid group request.", status=400)

        if group_user.role != 'admin':
            return session_handler.get_http_response(session_id, "User is not admin.", status=400)

        if not GroupChatUser.objects.filter(user=member, group=group).exists():
            return session_handler.get_http_response(session_id, "Member not in group.", status=400)

        group_user = GroupChatUser.objects.get(user=member, group=group)
        group_user.role = 'admin'
        group_user.save()
        return session_handler.get_http_response(session_id, "Member made admin.", status=200)

    return session_handler.get_http_response(session_id, "Invalid group request.", status=400)


def _get_session_id(request):
    return int(request.headers['session'].split(' ')[1])
