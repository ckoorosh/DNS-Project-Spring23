import os
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
        return jwt.encode(payload, self.secret, algorithm='HS256')

    def jwt_decode(self, token):
        return jwt.decode(token, self.secret, algorithms=['HS256'])
