import os
import time
from typing import Tuple

from MessangerServer.SecurityProtocols.RSAWithDHProtocol import RSAWithDHProtocol
from MessangerServer.SecurityProtocols.SymmetricSessionProtocol import SymmetricSessionProtocol
from MessangerServer.SecurityUtils.RSA import RSA
from MessangerServer.utlis import Singleton


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
        for session in self.sessions:
            if session.expiry < time.time():
                new_sessions[session.session_id] = session
        self.sessions = new_sessions

    def decrypt_message(self, message_bytes: bytes, message_nonce: bytes, session_id: int) -> str:
        session = self.sessions[session_id]
        return session.decrypt(message_bytes, message_nonce)

    def new_session_request(self, encrypted_message, mac):
        rsa_protocol = RSAWithDHProtocol(self.rsa)
        message, signature = rsa_protocol.server_phase1(encrypted_message, mac)
        key = rsa_protocol.get_derived_key()
        symmetric_protocol = SymmetricSessionProtocol(key)
        session = Session(rsa_protocol.session_id, symmetric_protocol)
        self.add_session(session)
        return session.session_id, message, signature
