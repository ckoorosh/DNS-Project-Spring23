import asyncio
import base64
import json
import os

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from MessangerServer.SecurityUtils.RSA import RSA
from MessangerServer.utlis import b64_to_bytes, JwtUtil
from MessangerServer.websocket_manager import WebsocketManager
from home.models import User, OTPreKey
from security.Session import SessionHandler


def _get_rsa():
    rsa = RSA()
    try:
        user = User.objects.get(username=os.getenv('SERVER_USERNAME'))
        rsa.set_private_pub(user.idk)
    except User.DoesNotExist:
        rsa.generate_key()
        user = User(
            username=os.getenv('SERVER_USERNAME'),
            idk=rsa.get_private()
        )
        user.save()
    return rsa


SessionHandler(_get_rsa())


@csrf_exempt
def get_rsa_pub(request):
    if request.method != 'GET':
        return invalid_request()

    response = json.dumps({'pub': _get_rsa().get_public()})
    return HttpResponse(content=response, content_type='application/json', status=200)


@csrf_exempt
def create_session(request):
    if request.method != 'POST':
        return invalid_request()
    encrypted_message = b64_to_bytes(request.POST['encrypted_message'])
    mac = request.POST['mac']
    encrypted_keys = b64_to_bytes(request.POST['encrypted_keys'])
    session_id, message, signature = SessionHandler().new_session_request(encrypted_keys, encrypted_message, mac)
    signature_str = base64.b64encode(signature).decode('utf-8')
    response_dict = {
        'message': message,
        'signature': signature_str
    }
    return HttpResponse(content=json.dumps(response_dict), content_type='application/json', status=200)


@csrf_exempt
def get_key_bundle(request):
    session_handler = SessionHandler()
    session_id = _get_session_id(request)
    headers, body = session_handler.decrypt_message(session_id, request.POST['nonce'], request.POST['message'])
    if request.method != 'POST':
        return invalid_request()
    username = body['username']
    try:
        user = User.objects.get(username=username)
        otp_key = OTPreKey.objects.filter(user=user).order_by('?').first()
        response = {
            'user_idk': user.idk,
            'user_prekey': user.signed_prekey,
            'user_prekey_signature': user.prekey_signature,
            'otprekey': otp_key.key,
            'otprekey_index': otp_key.index
        }
        otp_key.delete()

        return session_handler.get_http_response(session_id, response, 200)

    except User.DoesNotExist:
        return invalid_request()


@csrf_exempt
def send_x3dh(request):
    session_handler = SessionHandler()
    session_id = _get_session_id(request)
    headers, body = session_handler.decrypt_message(session_id, request.POST['nonce'], request.POST['message'])
    if request.method != 'POST':
        return invalid_request()
    username = body['username']
    try:
        token = headers['Authorization'].split(' ')[1]
        sender = JwtUtil().jwt_decode(token)['username']
        if WebsocketManager().is_user_online(username):
            body['sender'] = sender
            asyncio.run(WebsocketManager().send_message_to_user(username, f'1{json.dumps(body)}'))

        return session_handler.get_http_response(session_id, 'Ok', 200)

    except User.DoesNotExist:
        return invalid_request()


@csrf_exempt
def send_message(request):
    session_handler = SessionHandler()
    session_id = _get_session_id(request)
    headers, body = session_handler.decrypt_message(session_id, request.POST['nonce'], request.POST['message'])
    if request.method != 'POST':
        return invalid_request()
    username = body['username']
    try:
        token = headers['Authorization'].split(' ')[1]
        sender = JwtUtil().jwt_decode(token)['username']
        if WebsocketManager().is_user_online(username):
            body['sender'] = sender
            asyncio.run(WebsocketManager().send_message_to_user(username, f'2{json.dumps(body)}'))

        return session_handler.get_http_response(session_id, 'Ok', 200)

    except User.DoesNotExist:
        return invalid_request()


def invalid_request():
    return HttpResponse("Invalid request.", status=500)


def _get_session_id(request):
    return int(request.headers['session'].split(' ')[1])
