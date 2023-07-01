import json
from typing import Tuple, List

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from SecurityUtils.ChaCha import ChaCha20Poly1305
from SecurityUtils.DiffieHellman import ECDiffieHellman


class TripleDHProtocol:

    def __init__(self):
        self.start_side_idk = None
        self.start_side_ephemeral = None
        self.end_side_idk = None
        self.end_side_signed_prekey = None
        self.end_side_prekey_signature = None
        self.end_side_one_time_prekey = None
        self.end_side_otp_index = None
        self.shared_key = None

    def set_start_side(
            self,
            start_side_idk: ECDiffieHellman,
            end_side_idk: str,
            end_side_signed_prekey: str,
            end_side_prekey_signature: bytes,
            end_side_one_time_prekey: str,
            end_side_otp: int
    ):
        self.start_side_idk = start_side_idk

        self.start_side_ephemeral = ECDiffieHellman()
        self.start_side_ephemeral.generate_private_key()

        self.end_side_idk = ECDiffieHellman()
        self.end_side_idk.set_peer_pub(end_side_idk)

        if not self.end_side_idk.verify(end_side_prekey_signature, end_side_signed_prekey):
            raise Exception('Wrong signature for user public key!!')

        self.end_side_signed_prekey = ECDiffieHellman()
        self.end_side_signed_prekey.set_peer_pub(end_side_signed_prekey)

        self.end_side_one_time_prekey = ECDiffieHellman()
        self.end_side_one_time_prekey.set_peer_pub(end_side_one_time_prekey)

        self.end_side_otp_index = end_side_otp

    def set_end_side(
            self,
            start_side_idk: str,
            start_side_ephemeral: str,
            end_side_idk: ECDiffieHellman,
            end_side_signed_prekey: ECDiffieHellman,
            end_side_one_time_prekey: ECDiffieHellman,
    ):
        self.start_side_idk = ECDiffieHellman()
        self.start_side_ephemeral = ECDiffieHellman()

        self.start_side_idk.set_peer_pub(start_side_idk)
        self.start_side_ephemeral.set_peer_pub(start_side_ephemeral)

        self.end_side_idk = end_side_idk
        self.end_side_signed_prekey = end_side_signed_prekey
        self.end_side_one_time_prekey = end_side_one_time_prekey

    def start_side_message(self) -> Tuple[bytes, bytes]:
        dh1 = ECDiffieHellman()
        dh2 = ECDiffieHellman()
        dh3 = ECDiffieHellman()
        dh4 = ECDiffieHellman()

        dh1.private_key = self.start_side_idk.private_key
        dh1.peer_pub = self.end_side_signed_prekey.peer_pub

        dh2.private_key = self.start_side_ephemeral.private_key
        dh2.peer_pub = self.end_side_idk.peer_pub

        dh3.private_key = self.start_side_ephemeral.private_key
        dh3.peer_pub = self.end_side_signed_prekey.peer_pub

        dh4.private_key = self.start_side_ephemeral.private_key
        dh4.peer_pub = self.end_side_one_time_prekey.peer_pub

        k1 = dh1.get_derived_key()
        k2 = dh2.get_derived_key()
        k3 = dh3.get_derived_key()
        k4 = dh4.get_derived_key()

        self.shared_key = self.create_key([k1, k2, k3, k4])
        message_dict = {
            'start_side_pub': self.start_side_idk.get_my_pub(),
            'end_side_pub': self.end_side_idk.get_peer_pub()
        }
        message_to_encrypt = json.dumps(message_dict)
        chacha = ChaCha20Poly1305(self.shared_key)
        return chacha.encrypt(message_to_encrypt)

    def end_side_verify(self, message: bytes, nonce: bytes):
        dh1 = ECDiffieHellman()
        dh2 = ECDiffieHellman()
        dh3 = ECDiffieHellman()
        dh4 = ECDiffieHellman()

        dh1.peer_pub = self.start_side_idk.peer_pub
        dh1.private_key = self.end_side_signed_prekey.private_key

        dh2.peer_pub = self.start_side_ephemeral.peer_pub
        dh2.private_key = self.end_side_idk.private_key

        dh3.peer_pub = self.start_side_ephemeral.peer_pub
        dh3.private_key = self.end_side_signed_prekey.private_key

        dh4.peer_pub = self.start_side_ephemeral.peer_pub
        dh4.private_key = self.end_side_one_time_prekey.private_key

        k1 = dh1.get_derived_key()
        k2 = dh2.get_derived_key()
        k3 = dh3.get_derived_key()
        k4 = dh4.get_derived_key()
        self.shared_key = self.create_key([k1, k2, k3, k4])
        decrypted_message = ChaCha20Poly1305(self.shared_key).decrypt(nonce, message)
        decrypted_message_dict = json.loads(decrypted_message)
        if decrypted_message_dict.get('start_side_pub') != self.start_side_idk.get_peer_pub():
            raise Exception('Wrong message!!')
        elif decrypted_message_dict.get('end_side_pub') != self.end_side_idk.get_my_pub():
            raise Exception('Wrong message!!')

    def get_shared_key(self):
        return self.shared_key

    def create_key(self, bytes_array: List[bytes]) -> bytes:
        merged_shared_key = b''
        for key in bytes_array:
            merged_shared_key += key
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(merged_shared_key)
