import os
from threading import Lock

import jwt
from datetime import datetime, timezone, timedelta


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
