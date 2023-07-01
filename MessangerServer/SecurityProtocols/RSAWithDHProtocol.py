import json
import os
import random
import time
from typing import Tuple

from cryptography.hazmat.primitives import hashes

from MessangerServer.SecurityUtils.DiffieHellman import ECDiffieHellman
from MessangerServer.SecurityUtils.RSA import RSA


class RSAWithDHProtocol:

    def __init__(self, server_rsa: RSA):
        self.server_rsa = server_rsa
        self.dh = ECDiffieHellman()
        self.dh.generate_private_key()
        self.replay_attack_time_threshold = float(os.getenv('REPLAY_ATTACK_TIME_THRESHOLD'))
        self.hash = hashes.Hash(hashes.SHA256())
        self.nonce = None
        self.session_id = random.randint(0, 10000000000)

    def client_phase1(self, time_stamp: float) -> Tuple[bytes, str]:
        self.nonce = random.randint(0, 1000000000000)
        message_to_encrypt_dict = {
            'timestamp': time_stamp,
            'dh_pub': self.dh.get_my_pub(),
            'nonce': self.nonce
        }
        message_to_encrypt = json.dumps(message_to_encrypt_dict)
        encrypted_message = self.server_rsa.encrypt(message_to_encrypt)
        return encrypted_message, self.eval_hash(message_to_encrypt)

    def server_phase1(self, encrypted_message: bytes, message_hash: str) -> Tuple[str, bytes]:
        decrypted_message = self.server_rsa.decrypt(encrypted_message)
        if self.eval_hash(decrypted_message) != message_hash:
            raise Exception('Integrity Error!!')
        decrypted_message_dict = json.loads(decrypted_message)
        self.check_message(decrypted_message_dict)
        peer_dh_pub = decrypted_message_dict['dh_pub']
        self.dh.set_peer_pub(peer_dh_pub)
        message_to_sign_dict = {
            'timestamp': time.time(),
            'dh_pub': self.dh.get_my_pub(),
            'nonce': decrypted_message_dict['nonce'],
            'session_id': self.session_id,
            'expiry': int(os.getenv('SESSION_EXPIRY'))
        }
        message_to_sign = json.dumps(message_to_sign_dict)
        signature = self.server_rsa.sign(message_to_sign)
        return message_to_sign, signature

    def client_phase2(self, message: str, signature: bytes):
        if not self.server_rsa.verify(message, signature):
            raise Exception('Wrong signature by server!!')
        message_dict = json.loads(message)
        self.check_message(message_dict)
        peer_dh_pub = message_dict['dh_pub']
        self.dh.set_peer_pub(peer_dh_pub)

    def get_derived_key(self):
        return self.dh.get_derived_key()

    def check_message(self, message_dict):
        time_stamp = message_dict['timestamp']
        if time_stamp + self.replay_attack_time_threshold < time.time():
            raise Exception('It could be replay attack!!')
        if self.nonce is not None and self.nonce != int(message_dict['nonce']):
            raise Exception('It could be replay attack!!')

    def eval_hash(self, message: str) -> str:
        hash = self.hash.copy()
        hash.update(message.encode('utf-8'))
        return hash.finalize().hex()
