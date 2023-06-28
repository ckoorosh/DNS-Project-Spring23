from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def create_dh_params():
    return dh.generate_parameters(generator=2, key_size=2048)


def create_dh_private_key(params):
    return params.generate_private_key()


def get_dh_public_key(private_key):
    return private_key.public_key()


def join_dh_keys(private_key, public_key):
    shared_key = private_key.exchange(public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
