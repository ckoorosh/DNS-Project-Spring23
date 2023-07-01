import base64
import json
import os

from MessangerServer.SecurityUtils.RSA import RSA
from MessangerServer.utlis import b64_to_bytes
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from home.models import User
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


def invalid_request():
    return HttpResponse("Invalid request.", status=500)
