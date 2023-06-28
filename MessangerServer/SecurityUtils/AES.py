import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from utils import *


def create_aes_key():
    return os.urandom(32)


def create_aes_iv():
    return os.urandom(16)


def encrypt_aes(key, iv, message):
    message = convert_to_bytes(message)
    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(256).padder()
    padded_data = padder.update(message)
    padded_data += padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()


def decrypt_aes(key, iv, encoded_message):
    encoded_message = convert_to_bytes(encoded_message)
    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encoded_message) + decryptor.finalize()
    unpadder = padding.PKCS7(256).unpadder()
    return unpadder.update(decrypted) + unpadder.finalize()
