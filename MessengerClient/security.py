import hashlib
import json
import os
import secrets
import time
from typing import Tuple
import hashlib
import json

import requests

from SecurityProtocols.DoubleRatchetProtocol import DoubleRatchetProtocol
from SecurityProtocols.RSAWithDHProtocol import RSAWithDHProtocol
from SecurityProtocols.SymmetricSessionProtocol import SymmetricSessionProtocol
from SecurityProtocols.X3DHProtocol import TripleDHProtocol
from SecurityUtils.ChaCha import ChaCha20Poly1305
from SecurityUtils.DiffieHellman import ECDiffieHellman
from SecurityUtils.RSA import RSA
from SecurityUtils.utils import bytes_to_b64, b64_to_bytes
from SecurityUtils.ChaCha import ChaCha20Poly1305
from UserKeys import UserKeys
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
        elif decrypted_dict['content'].__class__ == dict:
            return decrypted_dict['content'], resp
        else:
            return json.loads(decrypted_dict['content']), resp

    def encrypt_str(self, text: str) -> Tuple[str, str]:
        nonce, encrypted_text = self.symmetric_protocol.encrypt_message(text)
        return bytes_to_b64(nonce), bytes_to_b64(encrypted_text)

    def decrypt_str(self, nonce: str, cipher: str) -> str:
        return self.symmetric_protocol.decrypt_message(b64_to_bytes(nonce), b64_to_bytes(cipher))

    @staticmethod
    def does_have_key(username):
        return UserKeys().chat_keys.__contains__(username)

    def exchange_key(self, key_bundle, username, token, me):
        exchange_protocol = TripleDHProtocol()
        my_keys = UserKeys()
        exchange_protocol.set_start_side(
            start_side_idk=my_keys.idk,
            end_side_idk=key_bundle['user_idk'],
            end_side_signed_prekey=key_bundle['user_prekey'],
            end_side_prekey_signature=b64_to_bytes(key_bundle['user_prekey_signature']),
            end_side_one_time_prekey=key_bundle['otprekey'],
            end_side_otp=int(key_bundle['otprekey_index'])
        )
        nonce, ad = exchange_protocol.start_side_message()
        message = {
            'nonce': bytes_to_b64(nonce),
            'ad': bytes_to_b64(ad),
            'start_side_idk': my_keys.idk.get_my_pub(),
            'start_side_ephemeral': exchange_protocol.start_side_ephemeral.get_my_pub(),
            'otp_index': int(key_bundle['otprekey_index']),
            'username': username
        }
        self.post(
            url=f'http://{os.getenv("SERVER_IP")}:{os.getenv("SERVER_PORT")}/sec/send_x3dh/',
            data=message,
            headers={
                'Authorization': f'Bearer {token}'
            }
        )

        self.set_double_ratchet(
            me=me,
            username=username,
            key=exchange_protocol.get_shared_key(),
            dh=exchange_protocol.start_side_ephemeral,
            receiver_pub=exchange_protocol.end_side_signed_prekey.get_peer_pub()
        )

    def set_double_ratchet(self, me, username, key, dh: ECDiffieHellman, receiver_pub: str):
        my_keys = UserKeys()
        dr = DoubleRatchetProtocol()
        dr.initialize(
            pre_shared_key=key,
            me=me,
            usernames=[me, username],
            my_dh=dh,
            receiver_pub=receiver_pub
        )
        my_keys.append_dr(username, dr)

    def answer_exchange_key(self, context, me: str):
        context = json.loads(context)

        exchange_protocol = TripleDHProtocol()
        my_keys = UserKeys()
        otp_index = int(context['otp_index'])
        exchange_protocol.set_end_side(
            start_side_idk=context['start_side_idk'],
            start_side_ephemeral=context['start_side_ephemeral'],
            end_side_idk=my_keys.idk,
            end_side_signed_prekey=my_keys.signed_prekey,
            end_side_one_time_prekey=my_keys.get_otp_key(otp_index)
        )
        exchange_protocol.end_side_verify(
            b64_to_bytes(context['ad']),
            b64_to_bytes(context['nonce'])
        )

        self.set_double_ratchet(
            me=me,
            username=context['sender'],
            key=exchange_protocol.get_shared_key(),
            dh=exchange_protocol.end_side_signed_prekey,
            receiver_pub=exchange_protocol.start_side_ephemeral.get_peer_pub()
        )

    def send_message_to_user(self, username: str, message: str, token: str):
        my_keys = UserKeys()
        dr = my_keys.chat_keys[username]
        nonce, encrypted_message = dr.send_message(username, message)
        self.post(
            url=f'http://{os.getenv("SERVER_IP")}:{os.getenv("SERVER_PORT")}/sec/send_message/',
            data={
                'nonce': bytes_to_b64(nonce),
                'cipher': bytes_to_b64(encrypted_message),
                'username': username
            },
            headers={'Authorization': f'Bearer {token}'}
        )

    def receive_message(self, context):
        my_keys = UserKeys()
        context = json.loads(context)
        sender = context['sender']
        dr = my_keys.chat_keys[sender]
        message = dr.received_message(sender, b64_to_bytes(context['cipher']), b64_to_bytes(context['nonce']))
        # Menu(None).add_to_buf(f'{sender}:  {message}')
        print(f'\n{sender}:  {message}\n')

    def save_chat(self, username, password, messages: list[dict]):
        messages = json.dumps(messages)
        file_key = hashlib.sha256(password.encode()).digest()  # todo: HKDF
        chacha = ChaCha20Poly1305(key=file_key)
        nonce, cipher = chacha.encrypt(messages)
        with open(f'chats/{username}.json', 'w') as f:
            save_dict = {'nonce': bytes_to_b64(nonce), 'cipher': bytes_to_b64(cipher)}
            f.write(json.dumps(save_dict))

    def load_chat(self, username, password):
        load_dict = json.load(open(f'chats/{username}.json', 'r'))
        file_key = hashlib.sha256(password.encode()).digest()  # todo: HKDF
        chacha = ChaCha20Poly1305(key=file_key)
        nonce = b64_to_bytes(load_dict['nonce'])
        cipher = b64_to_bytes(load_dict['cipher'])
        messages = chacha.decrypt(nonce, cipher)
        messages = json.loads(messages)
        return messages

    def add_group(self, group_id):
        UserKeys().add_group_key(group_id, secrets.token_bytes(32))

