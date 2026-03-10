import base64
import os
import hashlib
import hmac
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519, ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
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
        salt = os.urandom(16)  # fresh random salt prevents identical passwords hashing the same
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,           # 256-bit output key
        salt=salt,
        iterations=200_000,  # NIST-recommended minimum as of 2023; slows brute-force attacks
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
        # kdf.verify() does a constant-time comparison internally, which prevents
        # timing-based attacks that a naive `==` comparison would be vulnerable to.
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
    priv = rsa.generate_private_key(
        public_exponent=65537,  # F4; universally recommended — avoids small-exponent attacks
        key_size=2048
    )
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # caller encrypts with password separately
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
        # BestAvailableEncryption chooses the strongest PKCS#8 password-based
        # encryption scheme the library supports (currently AES-256-CBC + PBKDF2).
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )


def decrypt_private_key_pem(encrypted_private_pem: bytes, password: str):
    return serialization.load_pem_private_key(
        encrypted_private_pem,
        password=password.encode("utf-8"),
    )


def load_public_key(pem_or_der: bytes):
    """
    Load a public key from either PEM (-----BEGIN PUBLIC KEY-----) or
    raw DER/SPKI bytes.  The CLI client stores keys as PEM; the web client
    stores and transmits raw SPKI DER bytes.  Both formats are accepted here
    so that signature verification works for both clients.
    """
    # PEM files are ASCII text starting with '-----'
    if pem_or_der.lstrip()[:5] == b"-----":
        return serialization.load_pem_public_key(pem_or_der)
    # Otherwise treat as raw DER (SPKI)
    return serialization.load_der_public_key(pem_or_der)


# -------------------------
# File encryption (client)
# -------------------------
def encrypt_bytes_aesgcm(plaintext: bytes, dek: bytes) -> Tuple[bytes, bytes]:
    """
    Returns (nonce, ciphertext). AES-GCM with 12-byte nonce.
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
def wrap_dek_for_user(dek: bytes, recipient_rsa_public_pem: bytes) -> bytes:
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
# Signing (client)
# -------------------------
def make_upload_message(file_id: str, nonce: bytes, ciphertext: bytes, version: int) -> bytes:
    """
    Canonical byte string that is signed on upload/update/rotate.
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


def sign_bytes(data: bytes, ed25519_private_key) -> bytes:
    return ed25519_private_key.sign(data)


def verify_signature(data: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
    """
    Verify a signature over `data`.  Supports both:
      - Ed25519  (used by the Python CLI client)
      - ECDSA P-256 / SHA-256  (used by the browser/web client via WebCrypto)
    The key type is detected automatically from the loaded public key object.
    """
    try:
        pub = load_public_key(public_key_bytes)
        if isinstance(pub, ed25519.Ed25519PublicKey):
            # Ed25519: verify(signature, data) — no hash algorithm argument
            pub.verify(signature, data)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            # WebCrypto (browser) produces ECDSA signatures in IEEE P1363 format:
            # raw r || s concatenation (64 bytes for P-256).
            # Python's cryptography library expects DER/ASN.1 format.
            # Detect P1363 by checking if the signature length matches the curve
            # coordinate size (32 bytes each for P-256 = 64 bytes total).
            # DER signatures start with 0x30 (SEQUENCE tag) and are variable length.
            coord_size = (pub.key_size + 7) // 8  # e.g. 32 for P-256
            if len(signature) == 2 * coord_size and signature[0] != 0x30:
                # Convert P1363 (r || s) → DER SEQUENCE { INTEGER r, INTEGER s }
                r = int.from_bytes(signature[:coord_size], "big")
                s = int.from_bytes(signature[coord_size:], "big")
                signature = encode_dss_signature(r, s)
            # ECDSA: requires explicit hash algorithm
            pub.verify(signature, data, ECDSA(hashes.SHA256()))
        else:
            return False
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
