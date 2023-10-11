import json
from typing import Tuple

import cryptography
from MessangerServer.SecurityUtils.ChaCha import ChaCha20Poly1305
from MessangerServer.utlis import bytes_to_b64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa


class RSA:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_key(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()

    def get_public(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def get_private(self) -> str:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

    def set_private_pub(self, private: str):
        private_key_bytes = bytes(private, 'utf-8')
        recovered_private_key = serialization.load_pem_private_key(private_key_bytes, None)
        self.private_key = recovered_private_key
        self.public_key = self.private_key.public_key()

    def set_peer_public(self, peer_public: str):
        peer_pub_bytes = bytes(peer_public, 'utf-8')
        recovered_pub = serialization.load_pem_public_key(peer_pub_bytes)
        self.public_key = recovered_pub

    def sign(self, message: str) -> bytes:
        message_bytes = bytes(message, 'utf-8')
        return self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify(self, message: str, signature: bytes) -> bool:
        message_bytes = bytes(message, 'utf-8')
        try:
            self.public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except cryptography.exceptions.InvalidSignature:
            return False

    def encrypt(self, message: str) -> Tuple[bytes, bytes]:
        chacha = ChaCha20Poly1305()
        nonce, encrypted_message = chacha.encrypt(message)
        keys = {
            'nonce': bytes_to_b64(nonce),
            'key': bytes_to_b64(chacha.key)
        }
        keys_byte = bytes(json.dumps(keys), 'utf-8')
        return self.public_key.encrypt(
            keys_byte,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ), encrypted_message

    def decrypt(self, ciphertext: bytes) -> str:
        message_bytes = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return message_bytes.decode('utf-8')
