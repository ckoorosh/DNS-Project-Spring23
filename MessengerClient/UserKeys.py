import hashlib
import json
from typing import List, Dict

from SecurityProtocols.DoubleRatchetProtocol import DoubleRatchetProtocol, DoubleRatchetEncoder, DoubleRatchetDecoder
from SecurityUtils.ChaCha import ChaCha20Poly1305
from SecurityUtils.DiffieHellman import ECDiffieHellman, ECDiffieHellmanEncoder, ECDiffieHellmanDecoder
from SecurityUtils.utils import bytes_to_b64, b64_to_bytes
from utils import Singleton


class UserKeys(metaclass=Singleton):
    idk: ECDiffieHellman
    signed_prekey: ECDiffieHellman
    ot_prekeys: List[ECDiffieHellman]
    chat_keys: Dict[str, DoubleRatchetProtocol]
    group_keys: Dict[str, bytes]

    def __init__(self):
        self.chat_keys = {}
        self.group_keys = {}
        pass

    def generate(self):
        self.idk = ECDiffieHellman()
        self.idk.generate_private_key()
        self.signed_prekey = ECDiffieHellman()
        self.signed_prekey.generate_private_key()
        ot_prekeys_dh = []
        for i in range(100):
            dh = ECDiffieHellman()
            dh.generate_private_key()
            ot_prekeys_dh.append(dh)
        self.ot_prekeys = ot_prekeys_dh

    def get_public_keys(self):
        keys = UserSerializableKeys()
        keys.idk = self.idk.get_my_pub()
        keys.signed_prekey = self.signed_prekey.get_my_pub()
        keys.prekey_signature = bytes_to_b64(self.idk.sign(keys.signed_prekey))
        keys.ot_prekeys = {i: self.ot_prekeys[i].get_my_pub() for i in range(100)}
        return keys

    def get_private_keys(self):
        keys = UserSerializableKeys()
        keys.idk = self.idk.get_my_private()
        keys.signed_prekey = self.signed_prekey.get_my_private()
        keys.prekey_signature = ''
        keys.ot_prekeys = {i: self.ot_prekeys[i].get_my_private() for i in range(100)}
        return keys

    def get_otp_key(self, index) -> ECDiffieHellman:
        return self.ot_prekeys[index]

    def append_dr(self, username, dr):
        self.chat_keys[username] = dr

    def save_keys(self, username, password):
        keys = {'idk': json.dumps(self.idk, cls=ECDiffieHellmanEncoder),
                'signed_prekey': json.dumps(self.signed_prekey, cls=ECDiffieHellmanEncoder),
                'ot_prekeys': [json.dumps(self.ot_prekeys[i], cls=ECDiffieHellmanEncoder) for i in range(100)],
                'chat_keys': {username: json.dumps(self.chat_keys[username],
                                                   cls=DoubleRatchetEncoder) for username in self.chat_keys.keys()},
                'group_keys': {k: bytes_to_b64(v) for k, v in self.group_keys.keys()}
                }
        keys = json.dumps(keys)
        file_key = hashlib.sha256(password.encode()).digest()  # todo: HKDF
        chacha = ChaCha20Poly1305(key=file_key)
        nonce, cipher = chacha.encrypt(keys)
        with open(f'keys/{username}.json', 'w') as f:
            save_dict = {'nonce': bytes_to_b64(nonce), 'cipher': bytes_to_b64(cipher)}
            f.write(json.dumps(save_dict))

    def load_keys(self, username, password):
        load_dict = json.load(open(f'keys/{username}.json', 'r'))
        file_key = hashlib.sha256(password.encode()).digest() # todo: HKDF
        chacha = ChaCha20Poly1305(key=file_key)
        nonce = b64_to_bytes(load_dict['nonce'])
        cipher = b64_to_bytes(load_dict['cipher'])
        keys = chacha.decrypt(nonce, cipher)
        keys = json.loads(keys)
        self.idk = json.loads(keys['idk'], cls=ECDiffieHellmanDecoder)
        self.signed_prekey = json.loads(keys['signed_prekey'], cls=ECDiffieHellmanDecoder)
        self.ot_prekeys = [json.loads(keys['ot_prekeys'][i], cls=ECDiffieHellmanDecoder) for i in range(100)]
        self.chat_keys = {username: json.loads(keys['chat_keys'][username],
                                               cls=DoubleRatchetDecoder) for username in keys['chat_keys'].keys()}
        self.group_keys = {k: b64_to_bytes(v) for k, v in keys['group_keys'].items()}

    def add_group_key(self, group_id: str, key: bytes):
        self.group_keys[group_id] = key


class UserSerializableKeys:
    idk: str
    signed_prekey: str
    prekey_signature: str
    ot_prekeys: Dict[int, str]

    def __init__(self):
        pass
