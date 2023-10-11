import json

import cryptography
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class ECDiffieHellman:

    def __init__(self):
        self.private_key = None
        self.peer_pub = None

    def generate_private_key(self):
        self.private_key = ec.generate_private_key(ec.SECP384R1())

    def set_peer_pub(self, peer_pub: str):
        peer_pub_bytes = bytes(peer_pub, 'utf-8')
        recovered_pub = serialization.load_pem_public_key(peer_pub_bytes)
        self.peer_pub = recovered_pub

    def set_private_pub(self, private: str):
        private_key_bytes = bytes(private, 'utf-8')
        recovered_private_key = serialization.load_pem_private_key(private_key_bytes, None)
        self.private_key = recovered_private_key

    def get_my_pub(self) -> str:
        pub = self.private_key.public_key()
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pub_bytes.decode('utf-8')

    def get_my_private(self) -> str:
        pk_bytes = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        return pk_bytes.decode('utf-8')

    def get_my_private(self) -> str:
        pk_bytes = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        return pk_bytes.decode('utf-8')

    def get_peer_pub(self) -> str:
        pub_bytes = self.peer_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pub_bytes.decode('utf-8')

    def get_derived_key(self) -> bytes:
        shared_key = self.private_key.exchange(ec.ECDH(), self.peer_pub)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        return derived_key

    def sign(self, message: str) -> bytes:
        message_bytes = bytes(message, 'utf-8')

        return self.private_key.sign(
            message_bytes,
            ec.ECDSA(hashes.SHA256())
        )

    def verify(self, signature: bytes, message: str) -> bool:
        message_bytes = bytes(message, 'utf-8')
        try:
            self.peer_pub.verify(
                signature,
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except cryptography.exceptions.InvalidSignature:
            return False


class ECDiffieHellmanEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ECDiffieHellman):
            private = None if obj.private_key is None else obj.get_my_private()
            peer_pub = None if obj.peer_pub is None else obj.get_peer_pub()
            return {'private': private, 'peer_pub': peer_pub}
        return super().default(obj)


class ECDiffieHellmanDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        super().__init__(object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, dct):
        dh = ECDiffieHellman()
        if dct.get('private'):
            dh.set_private_pub(dct['private'])
        if dct.get('peer_pub'):
            dh.set_peer_pub(dct['peer_pub'])
        return dh
