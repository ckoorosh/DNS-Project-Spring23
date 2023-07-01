import json
import os
import time
from typing import Tuple

from django.http import HttpResponse

from MessangerServer.SecurityProtocols.RSAWithDHProtocol import RSAWithDHProtocol
from MessangerServer.SecurityProtocols.SymmetricSessionProtocol import SymmetricSessionProtocol
from MessangerServer.SecurityUtils.RSA import RSA
from MessangerServer.utlis import Singleton, b64_to_bytes, bytes_to_b64


class Session:
    def __init__(self, session_id: int, symmetric_session_protocol: SymmetricSessionProtocol):
        self.session_id = session_id
        self.expiry = float(os.getenv('SESSION_EXPIRY')) + time.time()
        self.symmetric_session_protocol = symmetric_session_protocol

    def decrypt(self, message_bytes: bytes, nonce: bytes) -> str:
        return self.symmetric_session_protocol.decrypt_message(nonce, message_bytes)

    def encrypt(self, message: str) -> Tuple[bytes, bytes]:
        return self.symmetric_session_protocol.encrypt_message(message)


class SessionHandler(metaclass=Singleton):
    def __init__(self, server_rsa: RSA = None):
        self.sessions = {}
        self.last_update = time.time()
        if server_rsa is None:
            raise Exception('Wrong input.')
        self.rsa = server_rsa

    def add_session(self, session: Session):
        self.update_session()
        self.sessions[session.session_id] = session

    def update_session(self):
        if self.last_update + 1000 > time.time():
            return
        new_sessions = {}
        for _, session in self.sessions.items():
            if session.expiry < time.time():
                new_sessions[session.session_id] = session
        self.sessions = new_sessions

    def decrypt_message(self, session_id: int, message_nonce: str, message: str):
        session = self.sessions[session_id]
        plain = session.decrypt(b64_to_bytes(message), b64_to_bytes(message_nonce))
        message_dict = json.loads(plain)
        return message_dict['headers'], message_dict['data']

    def decrypt_str(self, session_id: int, message_nonce: str, message: str) -> str:
        session = self.sessions[session_id]
        return session.decrypt(b64_to_bytes(message), b64_to_bytes(message_nonce))

    def new_session_request(self, encrypted_keys, encrypted_message, mac):
        rsa_protocol = RSAWithDHProtocol(self.rsa)
        message, signature = rsa_protocol.server_phase1(encrypted_message, encrypted_keys, mac)
        key = rsa_protocol.get_derived_key()
        symmetric_protocol = SymmetricSessionProtocol(key)
        session = Session(rsa_protocol.session_id, symmetric_protocol)
        self.add_session(session)
        return session.session_id, message, signature

    def get_http_response(self, session_id, content, status, content_type=None):
        if content.__class__ == str:
            t = 'str'
        else:
            t = 'json'
        message_dict = {
            'type': t,
            'content': content
        }
        message = json.dumps(message_dict)

        session = self.sessions[session_id]
        nonce, encrypted = session.encrypt(message)
        encrypted = {
            'nonce': bytes_to_b64(nonce),
            'data': bytes_to_b64(encrypted)
        }
        if content_type is None:
            return HttpResponse(content=json.dumps(encrypted), status=status)
        else:
            return HttpResponse(content=json.dumps(encrypted), status=status, content_type=content_type)

    def encrypt_message(self, session_id: int, message: str) -> Tuple[str, str]:
        session = self.sessions[session_id]
        nonce, encrypted_message = session.encrypt(message)
        return bytes_to_b64(nonce), bytes_to_b64(encrypted_message)
