from typing import List, Dict

from SecurityUtils.DiffieHellman import ECDiffieHellman


class UserKeys:
    idk: ECDiffieHellman
    signed_prekey: ECDiffieHellman
    ot_prekeys: List[ECDiffieHellman]

    def __init__(self):
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
        keys.prekey_signature = self.idk.sign(keys.signed_prekey)
        keys.ot_prekeys = {i: self.ot_prekeys[i].get_my_pub() for i in range(100)}
        return keys

    def get_private_keys(self):
        keys = UserSerializableKeys()
        keys.idk = self.idk.get_my_private()
        keys.signed_prekey = self.signed_prekey.get_my_private()
        keys.prekey_signature = ''
        keys.ot_prekeys = {i: self.ot_prekeys[i].get_my_private() for i in range(100)}
        return keys

    def load_keys(self, password):
        pass


class UserSerializableKeys:
    idk: str
    signed_prekey: str
    prekey_signature: str
    ot_prekeys: Dict[str, str]

    def __init__(self):
        pass
