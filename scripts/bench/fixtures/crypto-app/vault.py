"""Planted-issue fixture: a small file vault. Quantum-vulnerable and weak primitives are intentional."""
import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def make_identity():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def wrap_key(public_key, file_key: bytes) -> bytes:
    return public_key.encrypt(file_key, padding.PKCS1v15())


def sign_manifest(private_key, manifest: bytes) -> bytes:
    return private_key.sign(manifest, padding.PKCS1v15(), hashes.SHA1())


def encrypt_block(key: bytes, block: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(block) + enc.finalize()


def fingerprint(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def derive_key(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()


def new_file_key() -> bytes:
    return os.urandom(32)


def export_public(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
