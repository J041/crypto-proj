import base64
import os
import hashlib
import hmac
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# -------------------------
# Password hashing (server)
# -------------------------
def hash_password(password: str, salt: bytes | None = None) -> Tuple[bytes, bytes]:
    """
    Returns (salt, pw_hash). Uses PBKDF2-HMAC-SHA256.
    Store salt+hash on server.
    """
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    pw_hash = kdf.derive(password.encode("utf-8"))
    return salt, pw_hash


def verify_password(password: str, salt: bytes, pw_hash: bytes) -> bool:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    try:
        kdf.verify(password.encode("utf-8"), pw_hash)
        return True
    except Exception:
        return False


# -------------------------
# Keypairs (client-side)
# -------------------------
def generate_rsa_keypair() -> Tuple[bytes, bytes]:
    """
    Generates RSA-2048 keypair for key wrapping.
    Returns (private_pem, public_pem).
    """
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    """
    Generates Ed25519 signing keypair.
    Returns (private_pem, public_pem).
    """
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def encrypt_private_key_pem(private_pem: bytes, password: str) -> bytes:
    key = serialization.load_pem_private_key(private_pem, password=None)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )


def decrypt_private_key_pem(encrypted_private_pem: bytes, password: str):
    return serialization.load_pem_private_key(
        encrypted_private_pem,
        password=password.encode("utf-8"),
    )


def load_public_key(pem: bytes):
    return serialization.load_pem_public_key(pem)


# -------------------------
# File encryption (client)
# -------------------------
def encrypt_bytes_aesgcm(plaintext: bytes, dek: bytes) -> Tuple[bytes, bytes]:
    """
    Returns (nonce, ciphertext). AES-GCM with 12-byte nonce.
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(dek)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ct


def decrypt_bytes_aesgcm(nonce: bytes, ciphertext: bytes, dek: bytes) -> bytes:
    aesgcm = AESGCM(dek)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


# -------------------------
# Key wrapping (DEK) RSA-OAEP
# -------------------------
def wrap_dek_for_user(dek: bytes, recipient_rsa_public_pem: bytes) -> bytes:
    pub = load_public_key(recipient_rsa_public_pem)
    wrapped = pub.encrypt(
        dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return wrapped


def unwrap_dek_for_user(wrapped_dek: bytes, recipient_rsa_private_key) -> bytes:
    dek = recipient_rsa_private_key.decrypt(
        wrapped_dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return dek


# -------------------------
# Optional signing (client)
# -------------------------
def sign_bytes(data: bytes, ed25519_private_key) -> bytes:
    return ed25519_private_key.sign(data)


def verify_signature(data: bytes, signature: bytes, ed25519_public_pem: bytes) -> bool:
    try:
        pub = load_public_key(ed25519_public_pem)
        pub.verify(signature, data)
        return True
    except Exception:
        return False


# -------------------------
# Helpers
# -------------------------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))
