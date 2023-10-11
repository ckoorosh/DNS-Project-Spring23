import json
from typing import List, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from MessangerServer.SecurityUtils.ChaCha import ChaCha20Poly1305
from MessangerServer.SecurityUtils.DiffieHellman import ECDiffieHellman


class DoubleRatchetProtocol:

    def __init__(
            self,
            pre_shared_key: bytes,
            me: str,
            usernames: List[str],
            my_dh: ECDiffieHellman,
            receiver_pub: str
    ):
        self.rks = {
            username: self.derive_key(pre_shared_key, bytes(username, 'utf8'))[0]
            for username in usernames
        }
        self.me = me
        self.my_dh = my_dh
        self.receiver_pub = receiver_pub
        self.steps = {username: 1 for username in usernames}
        self.sym_keys = {
            username: self.derive_key(pre_shared_key, bytes(username, 'utf8'))[1]
            for username in usernames
        }

    def received_message(self, username: str, message: bytes, nonce: bytes) -> str:
        receiver_sym_key = self.sym_keys[username]
        chacha = ChaCha20Poly1305(receiver_sym_key)
        plain = chacha.decrypt(nonce, message)
        decrypted_message = json.loads(plain)
        self.receiver_pub = decrypted_message['dh_pub']
        self.my_dh.set_peer_pub(self.receiver_pub)
        dh_output = self.my_dh.get_derived_key()
        new_rk, new_sym_key = self.derive_key(dh_output, self.rks[username])
        self.rks[username] = new_rk
        self.sym_keys[username] = new_sym_key
        return decrypted_message['message']

    def send_message(self, username: str, message: str) -> Tuple[bytes, bytes]:
        sym_key = self.sym_keys[self.me]
        self.my_dh.generate_private_key()
        dh_output = self.my_dh.get_derived_key()
        new_rk, new_sym_key = self.derive_key(dh_output, self.rks[self.me])
        self.rks[self.me] = new_rk
        self.sym_keys[self.me] = new_sym_key
        message_to_encrypt_dict = {
            'dh_pub': self.my_dh.get_my_pub(),
            'message': message
        }
        chacha = ChaCha20Poly1305(sym_key)
        return chacha.encrypt(json.dumps(message_to_encrypt_dict))

    @staticmethod
    def derive_key(data, salt, ) -> Tuple[bytes, bytes]:
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=salt,
            info=b'handshake data',
        ).derive(data)

        return derived_key[:32], derived_key[32:]
