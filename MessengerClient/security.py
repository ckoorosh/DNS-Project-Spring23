import json
import os
import time
from typing import Tuple

import requests

from SecurityProtocols.RSAWithDHProtocol import RSAWithDHProtocol
from SecurityProtocols.SymmetricSessionProtocol import SymmetricSessionProtocol
from SecurityUtils.RSA import RSA
from SecurityUtils.utils import bytes_to_b64, b64_to_bytes
from utils import Singleton


class ClientSecurityHandler(metaclass=Singleton):
    server_pub: str
    symmetric_protocol: SymmetricSessionProtocol
    handshake_protocol: RSAWithDHProtocol

    def __init__(self):
        self.session = requests.Session()
        self.server_ip = os.getenv('SERVER_IP')
        self.server_port = int(os.getenv('SERVER_PORT'))
        self.session_id = 0
        self.start_session()

    def start_session(self):
        resp = self.session.get(f'http://{self.server_ip}:{self.server_port}/sec/get_rsa_pub/')
        self.server_pub = json.loads(resp.content)['pub']
        server_rsa = RSA()
        server_rsa.set_peer_public(self.server_pub)
        self.handshake_protocol = RSAWithDHProtocol(server_rsa)
        self.client_phase1()

    def client_phase1(self):
        encrypted_keys, encrypted_message, mac = self.handshake_protocol.client_phase1(time.time())
        data = {
            'encrypted_keys': bytes_to_b64(encrypted_keys),
            'encrypted_message': bytes_to_b64(encrypted_message),
            'mac': mac
        }
        resp = self.session.post(f'http://{self.server_ip}:{self.server_port}/sec/create_session/', data=data)
        resp_dict = json.loads(resp.content)
        self.handshake_protocol.client_phase2(
            resp_dict['message'],
            b64_to_bytes(resp_dict['signature'])
        )
        self.symmetric_protocol = SymmetricSessionProtocol(self.handshake_protocol.get_derived_key())
        self.session_id = json.loads(resp_dict['message'])['session_id']
        self.session.headers['session'] = f'Bearer {self.session_id}'

    def get(self, url):
        return self.session.get(url)

    def post(self, url, data=None, headers=None):
        if headers is None:
            headers = {}
        wrapped_data = {
            'headers': headers,
            'data': data
        }
        nonce, encrypted = self.symmetric_protocol.encrypt_message(json.dumps(wrapped_data))
        data_to_send = {
            'nonce': bytes_to_b64(nonce),
            'message': bytes_to_b64(encrypted)
        }
        resp = self.session.post(url, data=data_to_send)
        resp_dict = json.loads(resp.content)
        nonce = resp_dict['nonce']
        data = resp_dict['data']
        decrypted = self.symmetric_protocol.decrypt_message(b64_to_bytes(nonce), b64_to_bytes(data))
        decrypted_dict = json.loads(decrypted)
        t = decrypted_dict['type']
        if t == 'str':
            return decrypted_dict['content'], resp
        else:
            return json.loads(decrypted_dict['content']), resp

    def encrypt_str(self, text: str) -> Tuple[str, str]:
        nonce, encrypted_text = self.symmetric_protocol.encrypt_message(text)
        return bytes_to_b64(nonce), bytes_to_b64(encrypted_text)

    def decrypt_str(self, nonce: str, cipher: str) -> str:
        return self.symmetric_protocol.decrypt_message(b64_to_bytes(nonce), b64_to_bytes(cipher))
