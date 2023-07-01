import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

from utils import *


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
        )

    def get_private(self) -> str:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

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

    def encrypt(self, message: str) -> bytes:
        message_bytes = bytes(message, 'utf-8')
        return self.public_key.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

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
