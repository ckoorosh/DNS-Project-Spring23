import base64
import os
from datetime import datetime, timezone, timedelta
from threading import Lock

import jwt


class Singleton(type):
    _instances = {}
    _lock: Lock = Lock()

    def __call__(cls, *args, **kwargs):
        with cls._lock:
            if cls not in cls._instances:
                instance = super().__call__(*args, **kwargs)
                cls._instances[cls] = instance
        return cls._instances[cls]


class JwtUtil(metaclass=Singleton):
    def __init__(self):
        self.secret = os.getenv('JWT_PASSWORD', 'pass')

    def jwt_encode(self, payload):
        payload['exp'] = datetime.now(tz=timezone.utc) + timedelta(days=1)
        return jwt.encode(payload, self.secret, algorithm='HS256')

    def jwt_decode(self, token):
        try:
            return jwt.decode(token, self.secret, algorithms=['HS256'])
        except jwt.exceptions.ExpiredSignatureError:
            return None


def b64_to_bytes(string: str) -> bytes:
    return base64.b64decode(string)


def bytes_to_b64(bytes_data: bytes) -> str:
    return base64.b64encode(bytes_data).decode('utf-8')
