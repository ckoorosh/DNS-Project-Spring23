import json
import os
from typing import Tuple

from SecurityUtils.ChaCha import ChaCha20Poly1305


class SymmetricSessionProtocol:
    def __init__(self, key: bytes):
        self.encryption_module = ChaCha20Poly1305(key)
        self.nonce_window_size = int(os.getenv('SESSION_WINDOW_SIZE'))
        self.nonce_window = [0] * self.nonce_window_size
        self.last_received_nonce = 0
        self.last_used_nonce = 0

    def encrypt_message(self, message: str, additional_data: str = None) -> Tuple[bytes, bytes]:
        self.last_used_nonce += 1
        nonce = self.last_used_nonce
        message_to_encrypt_dict = {
            'nonce': nonce,
            'message': message
        }
        message_to_encrypt = json.dumps(message_to_encrypt_dict)
        return self.encryption_module.encrypt(message_to_encrypt, additional_data)

    def decrypt_message(self, nonce: bytes, cipher: bytes, additional_data: str = None) -> str:
        plain = self.encryption_module.decrypt(nonce, cipher, additional_data)
        message_dict = json.loads(plain)
        self.check_and_update(message_dict)
        return message_dict['message']

    def check_and_update(self, message_dict):
        nonce = message_dict['nonce']
        if nonce < self.last_received_nonce - self.nonce_window_size:
            raise Exception('Expired nonce.')

        if nonce > self.last_received_nonce:
            self.last_received_nonce = nonce

        nonce_index = self.last_received_nonce - nonce
        if self.nonce_window[nonce_index] == nonce:
            raise Exception('Replayed request!!')
        self.nonce_window[nonce_index] = nonce
