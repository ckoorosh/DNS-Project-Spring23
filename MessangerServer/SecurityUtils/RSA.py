from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from utils import *


def create_rsa_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def encode_rsa_private(key, password):
    password = convert_to_bytes(password)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )


def decode_rsa_private(coded_key, password):
    password = convert_to_bytes(password)
    coded_key = convert_to_bytes(coded_key)
    return serialization.load_pem_private_key(
        coded_key,
        password=password,
    )


def encode_rsa_public(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def decode_rsa_public(coded_key):
    coded_key = convert_to_bytes(coded_key)
    return load_pem_public_key(coded_key)


def sign_rsa(key, message):
    message = convert_to_bytes(message)
    return key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_rsa(key, signature, message):
    message = convert_to_bytes(message)
    signature = convert_to_bytes(signature)
    return key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def encrypt(key, message):
    message = convert_to_bytes(message)
    return key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt(key, encrypted_message):
    encrypted_message = convert_to_bytes(encrypted_message)
    return key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
