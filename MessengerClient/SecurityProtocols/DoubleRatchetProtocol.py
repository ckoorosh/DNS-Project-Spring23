import json
from typing import List, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from SecurityUtils.ChaCha import ChaCha20Poly1305
from SecurityUtils.DiffieHellman import ECDiffieHellman, ECDiffieHellmanEncoder, ECDiffieHellmanDecoder
from SecurityUtils.utils import bytes_to_b64, b64_to_bytes


class DoubleRatchetProtocol:

    def __init__(self):
        self.rks = {}
        self.me = None
        self.my_dh = None
        self.receiver_pub = None
        self.sym_keys = {}

    def initialize(
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
        self.my_dh.set_peer_pub(self.receiver_pub)
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

    def get_rks(self):
        rks = {}
        for username, rk in self.rks.items():
            rks[username] = bytes_to_b64(rk)
        return rks

    def get_sym_keys(self):
        sym_keys = {}
        for username, sk in self.rks.items():
            sym_keys[username] = bytes_to_b64(sk)
        return sym_keys

    @staticmethod
    def derive_key(data, salt, ) -> Tuple[bytes, bytes]:
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=salt,
            info=b'handshake data',
        ).derive(data)

        return derived_key[:32], derived_key[32:]


class DoubleRatchetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, DoubleRatchetProtocol):
            rks = obj.get_rks()
            my_dh = json.dumps(obj.my_dh, cls=ECDiffieHellmanEncoder)
            sym_keys = obj.get_sym_keys()

            return {'rks': rks, 'me': obj.me,'receiver_pub':obj.receiver_pub, 'my_dh': my_dh, 'sym_keys': sym_keys}
        return super().default(obj)


class DoubleRatchetDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        super().__init__(object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, dct):
        dr = DoubleRatchetProtocol()
        dr.my_dh = json.loads(dct['my_dh'], cls=ECDiffieHellmanDecoder)
        dr.receiver_pub = dct['receiver_pub']
        rks_dict = json.loads(dct['rks'])
        sym_dict = json.loads(dct['sym_keys'])
        for k,v in rks_dict.items():
            rks_dict[k] = b64_to_bytes(v)
        for k,v in sym_dict.items():
            sym_dict[k]=b64_to_bytes(v)

        dr.rks = rks_dict
        dr.sym_keys = sym_dict
            
        return dr
