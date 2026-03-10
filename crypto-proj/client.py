import argparse
import os
from pathlib import Path

import requests

from crypto_utils import (
    generate_rsa_keypair, generate_ed25519_keypair,
    encrypt_private_key_pem, decrypt_private_key_pem,
    wrap_dek_for_user, unwrap_dek_for_user,
    encrypt_bytes_aesgcm, decrypt_bytes_aesgcm,
    sign_bytes, verify_signature, make_upload_message,
    b64e, b64d
)

CLIENT_DIR = Path.home() / ".acrypt_client"


def user_dir(username: str) -> Path:
    d = CLIENT_DIR / username
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_bytes(p: Path, b: bytes):
    p.write_bytes(b)


def load_bytes(p: Path) -> bytes:
    return p.read_bytes()


def keys_exist(username: str) -> bool:
    d = user_dir(username)
    return all((d / n).exists() for n in ["rsa_priv.pem", "rsa_pub.pem", "sign_priv.pem", "sign_pub.pem"])


def register(server: str, username: str, password: str):
    if not keys_exist(username):
        rsa_priv, rsa_pub = generate_rsa_keypair()
        sign_priv, sign_pub = generate_ed25519_keypair()

        save_bytes(user_dir(username) / "rsa_pub.pem", rsa_pub)
        save_bytes(user_dir(username) / "sign_pub.pem", sign_pub)

        save_bytes(user_dir(username) / "rsa_priv.pem", encrypt_private_key_pem(rsa_priv, password))
        save_bytes(user_dir(username) / "sign_priv.pem", encrypt_private_key_pem(sign_priv, password))

    rsa_pub = load_bytes(user_dir(username) / "rsa_pub.pem")
    sign_pub = load_bytes(user_dir(username) / "sign_pub.pem")

    r = requests.post(f"{server}/register", json={
        "username": username,
        "password": password,
        "rsa_pub_pem_b64": b64e(rsa_pub),
        "sign_pub_pem_b64": b64e(sign_pub),
    })
    print(r.status_code, r.text)


def login(server: str, username: str, password: str) -> str:
    r = requests.post(f"{server}/login", json={"username": username, "password": password})
    r.raise_for_status()
    token = r.json()["token"]
    save_bytes(user_dir(username) / "token.txt", token.encode("utf-8"))
    return token


def load_token(username: str) -> str:
    return load_bytes(user_dir(username) / "token.txt").decode("utf-8").strip()


def load_private_keys(username: str, password: str):
    rsa_priv_enc = load_bytes(user_dir(username) / "rsa_priv.pem")
    sign_priv_enc = load_bytes(user_dir(username) / "sign_priv.pem")
    rsa_priv = decrypt_private_key_pem(rsa_priv_enc, password)
    sign_priv = decrypt_private_key_pem(sign_priv_enc, password)
    return rsa_priv, sign_priv


def get_user_rsa_pub(server: str, username: str) -> bytes:
    r = requests.get(f"{server}/user_pubkeys/{username}")
    r.raise_for_status()
    return b64d(r.json()["rsa_pub_pem_b64"])


def upload(server: str, username: str, password: str, filepath: str):
    token = load_token(username)
    rsa_priv, sign_priv = load_private_keys(username, password)

    plaintext = Path(filepath).read_bytes()
    dek = os.urandom(32)  # per-file symmetric key
    nonce, ciphertext = encrypt_bytes_aesgcm(plaintext, dek)

    # Wrap DEK for the owner (you)
    rsa_pub = load_bytes(user_dir(username) / "rsa_pub.pem")
    wrapped_for_owner = wrap_dek_for_user(dek, rsa_pub)

    # Generate the file_id client-side so it can be included in the signed message
    # before the server sees the upload. The server uses whichever file_id arrives
    # in the request body (falling back to its own random ID only if omitted), so
    # both sides agree on the ID that was signed.
    import secrets as _secrets  # local import avoids shadowing the top-level 'os' namespace
    file_id = _secrets.token_urlsafe(16)
    version = 1
    msg = make_upload_message(file_id, nonce, ciphertext, version)
    signature = sign_bytes(msg, sign_priv)

    r = requests.post(
        f"{server}/upload",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "file_id": file_id,
            "filename": Path(filepath).name,
            "nonce_b64": b64e(nonce),
            "ciphertext_b64": b64e(ciphertext),
            "wrapped_dek_b64": b64e(wrapped_for_owner),
            "sig_b64": b64e(signature),
        }
    )
    print(r.status_code, r.text)


def list_files(server: str, username: str):
    token = load_token(username)
    r = requests.get(f"{server}/list", headers={"Authorization": f"Bearer {token}"})
    print(r.status_code)
    print(r.text)


def download(server: str, username: str, password: str, file_id: str, outpath: str):
    token = load_token(username)
    # Only the RSA private key is needed for download (to unwrap the DEK).
    # The signing key (_) is not used here; signature verification uses the
    # signer's *public* key fetched from the server instead.
    rsa_priv, _ = load_private_keys(username, password)

    r = requests.get(f"{server}/download/{file_id}", headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    j = r.json()

    nonce = b64d(j["nonce_b64"])
    ciphertext = b64d(j["ciphertext_b64"])
    wrapped = b64d(j["wrapped_dek_b64"])

    # Verify the uploader's signature over the ciphertext before decrypting
    sig_b64 = j.get("sig_b64") or ""
    signer = j.get("signer") or ""
    if sig_b64 and signer:
        sig = b64d(sig_b64)
        signer_pub_resp = requests.get(f"{server}/user_pubkeys/{signer}")
        signer_pub_resp.raise_for_status()
        signer_pub_pem = b64d(signer_pub_resp.json()["sign_pub_pem_b64"])
        msg = make_upload_message(file_id, nonce, ciphertext, j["version"])
        if not verify_signature(msg, sig, signer_pub_pem):
            print(f"⚠️  WARNING: signature verification FAILED for file {file_id} (signer={signer}). "
                  "The ciphertext may have been tampered with by the server.")
        else:
            print(f"✅ Signature verified: ciphertext signed by {signer} at version {j['version']}")
    else:
        print("⚠️  WARNING: no signature present for this file.")

    dek = unwrap_dek_for_user(wrapped, rsa_priv)
    plaintext = decrypt_bytes_aesgcm(nonce, ciphertext, dek)

    Path(outpath).write_bytes(plaintext)
    print(f"Saved to {outpath}")


def grant(server: str, username: str, password: str, file_id: str, recipient: str):
    token = load_token(username)
    # Only the RSA private key is needed to unwrap the DEK; signing key unused here.
    rsa_priv, _ = load_private_keys(username, password)

    # Download your wrapped key so you can recover DEK
    r = requests.get(f"{server}/download/{file_id}", headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    j = r.json()
    dek = unwrap_dek_for_user(b64d(j["wrapped_dek_b64"]), rsa_priv)

    # Wrap for recipient using recipient's public key
    recipient_pub = get_user_rsa_pub(server, recipient)
    wrapped_for_recipient = wrap_dek_for_user(dek, recipient_pub)

    rr = requests.post(
        f"{server}/grant",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "file_id": file_id,
            "recipient": recipient,
            "wrapped_dek_b64": b64e(wrapped_for_recipient),
        }
    )
    print(rr.status_code, rr.text)


def modify(server: str, username: str, password: str, file_id: str, filepath: str):
    """
    Re-encrypt a locally modified file using the existing DEK for this file,
    then push the new ciphertext to the server.  The DEK is not changed, so all
    currently authorised users can still decrypt the updated file.
    The upload is signed with the user's Ed25519 signing key.
    """
    token = load_token(username)
    rsa_priv, sign_priv = load_private_keys(username, password)

    # Fetch current wrapped DEK for this user and current version
    r = requests.get(f"{server}/download/{file_id}", headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    j = r.json()
    dek = unwrap_dek_for_user(b64d(j["wrapped_dek_b64"]), rsa_priv)
    new_version = int(j["version"]) + 1

    # Encrypt the new plaintext with the same DEK
    plaintext = Path(filepath).read_bytes()
    nonce, ciphertext = encrypt_bytes_aesgcm(plaintext, dek)

    # Sign the new ciphertext
    msg = make_upload_message(file_id, nonce, ciphertext, new_version)
    signature = sign_bytes(msg, sign_priv)

    rr = requests.post(
        f"{server}/update",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "file_id": file_id,
            "nonce_b64": b64e(nonce),
            "ciphertext_b64": b64e(ciphertext),
            "sig_b64": b64e(signature),
        }
    )
    print(rr.status_code, rr.text)


def revoke(server: str, username: str, file_id: str, recipient: str):
    token = load_token(username)
    rr = requests.post(
        f"{server}/revoke",
        headers={"Authorization": f"Bearer {token}"},
        json={"file_id": file_id, "recipient": recipient}
    )
    print(rr.status_code, rr.text)


def rotate(server: str, username: str, password: str, file_id: str, allowed_users: list[str]):
    """
    Strong revocation: re-encrypt under a fresh DEK and re-wrap only for allowed users.
    The new ciphertext is signed with the owner's Ed25519 signing key.
    """
    token = load_token(username)
    rsa_priv, sign_priv = load_private_keys(username, password)

    r = requests.get(f"{server}/download/{file_id}", headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    j = r.json()

    old_nonce = b64d(j["nonce_b64"])
    old_ct = b64d(j["ciphertext_b64"])
    old_wrapped = b64d(j["wrapped_dek_b64"])
    old_dek = unwrap_dek_for_user(old_wrapped, rsa_priv)

    plaintext = decrypt_bytes_aesgcm(old_nonce, old_ct, old_dek)

    new_dek = os.urandom(32)
    new_nonce, new_ct = encrypt_bytes_aesgcm(plaintext, new_dek)

    wrapped_map = {}
    for u in allowed_users:
        pub = get_user_rsa_pub(server, u)
        wrapped_map[u] = b64e(wrap_dek_for_user(new_dek, pub))

    new_version = int(j["version"]) + 1
    msg = make_upload_message(file_id, new_nonce, new_ct, new_version)
    signature = sign_bytes(msg, sign_priv)

    rr = requests.post(
        f"{server}/rotate",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "file_id": file_id,
            "nonce_b64": b64e(new_nonce),
            "ciphertext_b64": b64e(new_ct),
            "sig_b64": b64e(signature),
            "wrapped_map": wrapped_map,
        }
    )
    print(rr.status_code, rr.text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="http://127.0.0.1:5000")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("register")
    p.add_argument("username")
    p.add_argument("password")

    p = sub.add_parser("login")
    p.add_argument("username")
    p.add_argument("password")

    p = sub.add_parser("upload")
    p.add_argument("username")
    p.add_argument("password")
    p.add_argument("filepath")

    p = sub.add_parser("list")
    p.add_argument("username")

    p = sub.add_parser("download")
    p.add_argument("username")
    p.add_argument("password")
    p.add_argument("file_id")
    p.add_argument("outpath")

    p = sub.add_parser("grant")
    p.add_argument("username")
    p.add_argument("password")
    p.add_argument("file_id")
    p.add_argument("recipient")

    p = sub.add_parser("modify")
    p.add_argument("username")
    p.add_argument("password")
    p.add_argument("file_id")
    p.add_argument("filepath")

    p = sub.add_parser("revoke")
    p.add_argument("username")
    p.add_argument("file_id")
    p.add_argument("recipient")

    p = sub.add_parser("rotate")
    p.add_argument("username")
    p.add_argument("password")
    p.add_argument("file_id")
    p.add_argument("allowed_users", nargs="+")  # include owner!

    args = ap.parse_args()

    if args.cmd == "register":
        register(args.server, args.username, args.password)
    elif args.cmd == "login":
        t = login(args.server, args.username, args.password)
        print("token saved")
    elif args.cmd == "upload":
        upload(args.server, args.username, args.password, args.filepath)
    elif args.cmd == "list":
        list_files(args.server, args.username)
    elif args.cmd == "download":
        download(args.server, args.username, args.password, args.file_id, args.outpath)
    elif args.cmd == "grant":
        grant(args.server, args.username, args.password, args.file_id, args.recipient)
    elif args.cmd == "modify":
        modify(args.server, args.username, args.password, args.file_id, args.filepath)
    elif args.cmd == "revoke":
        revoke(args.server, args.username, args.file_id, args.recipient)
    elif args.cmd == "rotate":
        rotate(args.server, args.username, args.password, args.file_id, args.allowed_users)


if __name__ == "__main__":
    main()
