import jwt
from django.http import HttpResponse
import json

secret = "SrsiAoYFywdn5d9acUvVVRtTfdfJVl8VxqU6V6QI0zU"

def jwt_encode(payload):
    return jwt.encode(payload, secret, algorithm='HS256')

def jwt_decode(token):
    return jwt.decode(token, secret, algorithms=['HS256'])
