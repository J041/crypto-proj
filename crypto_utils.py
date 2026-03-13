import base64
import os
import hashlib
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# -------------------------
# Password hashing (server)
# -------------------------
def hash_password(password: str, salt: bytes | None = None) -> Tuple[bytes, bytes]:
    """
    Returns (salt, pw_hash). Uses PBKDF2-HMAC-SHA256.
    Store salt+hash on server; never store the plaintext password.
    """
    if salt is None:
        salt = os.urandom(16)  # fresh random salt prevents identical passwords hashing the same
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,           # 256-bit output key
        salt=salt,
        iterations=600_000,  # 
    )
    pw_hash = kdf.derive(password.encode("utf-8"))
    return salt, pw_hash


def verify_password(password: str, salt: bytes, pw_hash: bytes) -> bool:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    try:
        # kdf.verify() does a constant-time comparison internally, which prevents
        # timing-based attacks that a naive `==` comparison would be vulnerable to.
        kdf.verify(password.encode("utf-8"), pw_hash)
        return True
    except Exception:
        return False


# -------------------------
# File encryption
# -------------------------
def encrypt_bytes_aesgcm(plaintext: bytes, dek: bytes) -> Tuple[bytes, bytes]:
    """
    Returns (nonce, ciphertext). AES-256-GCM with a fresh 96-bit nonce.
    File encryption is performed client-side in the browser via WebCrypto;
    this function exists for server-side utility use only.
    """
    # 96-bit nonce is the GCM standard size; it allows the most efficient
    # internal counter derivation and must never be reused under the same key.
    nonce = os.urandom(12)
    aesgcm = AESGCM(dek)
    # associated_data=None means no extra plaintext is authenticated alongside
    # the ciphertext. The GCM tag still covers the ciphertext itself.
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ct


def decrypt_bytes_aesgcm(nonce: bytes, ciphertext: bytes, dek: bytes) -> bytes:
    aesgcm = AESGCM(dek)
    # decrypt() raises InvalidTag if the authentication tag doesn't match,
    # catching any ciphertext tampering before plaintext is returned.
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


# -------------------------
# Key wrapping (DEK) RSA-OAEP
# -------------------------
def load_public_key(pem_or_der: bytes):
    """
    Load a public key from either PEM (-----BEGIN PUBLIC KEY-----) or
    raw DER/SPKI bytes. The web client stores and transmits raw SPKI DER bytes,
    so both formats are accepted here to ensure signature verification works correctly.
    """
    # PEM files are ASCII text starting with '-----'
    if pem_or_der.lstrip()[:5] == b"-----":
        return serialization.load_pem_public_key(pem_or_der)
    # Otherwise treat as raw DER (SPKI)
    return serialization.load_der_public_key(pem_or_der)


def wrap_dek_for_user(dek: bytes, recipient_rsa_public_pem: bytes) -> bytes:
    """
    RSA-OAEP encrypt (wrap) the DEK for a recipient using their RSA public key.
    This is performed client-side in the browser; the server never sees the unwrapped DEK.
    """
    pub = load_public_key(recipient_rsa_public_pem)
    wrapped = pub.encrypt(
        dek,
        padding.OAEP(
            # MGF1 with SHA-256 is the mask generation function for OAEP;
            # using SHA-256 for both the hash and MGF1 is the standard recommendation.
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,  # OAEP label is optional; None means no label (the common case)
        ),
    )
    return wrapped


def unwrap_dek_for_user(wrapped_dek: bytes, recipient_rsa_private_key) -> bytes:
    """
    RSA-OAEP decrypt (unwrap) a wrapped DEK using the recipient's RSA private key.
    """
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
# Signing (server-side verification)
# -------------------------
def make_upload_message(file_id: str, nonce: bytes, ciphertext: bytes, version: int) -> bytes:
    """
    Canonical byte string that is signed by the web client on upload/update/rotate,
    and verified by the server.
    Format: b"file_id:<file_id>|version:<version>|nonce:<nonce_hex>|ciphertext_sha256:<hex>"
    Using a structured, human-readable format makes the signed payload auditable.
    """
    ct_digest = hashlib.sha256(ciphertext).hexdigest()
    msg = (
        f"file_id:{file_id}|"
        f"version:{version}|"
        f"nonce:{nonce.hex()}|"
        f"ciphertext_sha256:{ct_digest}"
    ).encode("utf-8")
    return msg


def verify_signature(data: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
    """
    Verify an ECDSA P-256 / SHA-256 signature produced by the browser's WebCrypto API.

    WebCrypto produces ECDSA signatures in IEEE P1363 format: a raw 64-byte
    concatenation of the r and s integers. Python's cryptography library expects
    DER/ASN.1 encoding. P1363 is detected by checking that the signature length
    matches 2 * coord_size (64 bytes for P-256) and does not start with 0x30
    (the DER SEQUENCE tag). When detected, r and s are extracted and re-encoded
    as a DER SEQUENCE before verification.
    """
    try:
        pub = load_public_key(public_key_bytes)
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            return False

        coord_size = (pub.key_size + 7) // 8  # e.g. 32 bytes for P-256
        if len(signature) == 2 * coord_size and signature[0] != 0x30:
            # Convert IEEE P1363 (r || s) -> DER SEQUENCE { INTEGER r, INTEGER s }
            r = int.from_bytes(signature[:coord_size], "big")
            s = int.from_bytes(signature[coord_size:], "big")
            signature = encode_dss_signature(r, s)

        # ECDSA requires an explicit hash algorithm argument
        pub.verify(signature, data, ECDSA(hashes.SHA256()))
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
