import os
import secrets
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as ChaCha20Poly1305Lib


class ChaCha20Poly1305:

    def __init__(self, key: bytes = None):
        if key is None:
            key = secrets.token_bytes(32)
        self.key = key
        self.chacha = ChaCha20Poly1305Lib(key)

    def encrypt(self, message: str, additional_data: str = None) -> Tuple[bytes, bytes]:
        additional_data_bytes = None if additional_data is None else bytes(additional_data, 'utf-8')
        message_bytes = bytes(message, 'utf-8')
        nonce = os.urandom(12)
        return nonce, self.chacha.encrypt(nonce, message_bytes, additional_data_bytes)

    def decrypt(self, nonce: bytes, cipher: bytes, additional_data: str = None) -> str:
        additional_data_bytes = None if additional_data is None else bytes(additional_data, 'utf-8')
        decrypted = self.chacha.decrypt(nonce, cipher, additional_data_bytes)
        return decrypted.decode('utf-8')
