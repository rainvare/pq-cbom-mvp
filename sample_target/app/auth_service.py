"""Ejemplo con criptografia mixta, usado como target de prueba del scanner."""

import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generate_signing_key():
    """Genera un par de claves RSA de 2048 bits."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def generate_session_key():
    """Genera un par de claves ECDH sobre la curva P-256."""
    return ec.generate_private_key(ec.SECP256R1())


def hash_password(password: str) -> str:
    """Hashea `password` con MD5 y devuelve el digest en hexadecimal."""
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_legacy_compat(password: str) -> str:
    """Hashea `password` con SHA-1 y devuelve el digest en hexadecimal."""
    return hashlib.sha1(password.encode()).hexdigest()


def hash_token(token: str) -> str:
    """Hashea `token` con SHA-256 y devuelve el digest en hexadecimal."""
    return hashlib.sha256(token.encode()).hexdigest()


def encrypt_payload(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Cifra `data` con AES-256-GCM usando `key` e `iv`."""
    cipher = Cipher(algorithms.AES256(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()
