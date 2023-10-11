import base64
import json

from cryptography.hazmat.primitives import hashes


class UnknownTypeException(Exception):
    def __init__(self):
        self.message = 'unknown type!'


def convert_to_bytes(data_in):
    if isinstance(data_in, str):
        return data_in.encode()
    if isinstance(data_in, dict):
        return json.dumps(data_in)
    if isinstance(data_in, bytes):
        return data_in
    else:
        raise UnknownTypeException


def hash_sha256(message):
    message = convert_to_bytes(message)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    return digest.finalize()


def b64_to_bytes(string: str) -> bytes:
    return base64.b64decode(string)


def bytes_to_b64(bytes_data: bytes) -> str:
    return base64.b64encode(bytes_data).decode('utf-8')
