import base64
import os
import sqlite3
import secrets
import time
from pathlib import Path
from typing import Optional

from flask import Flask, request, jsonify, send_file, abort
from flask_cors import CORS

from crypto_utils import hash_password, verify_password, verify_signature, make_upload_message

APP = Flask(__name__)
CORS(APP)

DATA_DIR = Path("server_data")
DB_PATH = DATA_DIR / "server.db"
FILES_DIR = DATA_DIR / "files"
TOKEN_TTL_SECONDS = 60 * 60 * 8  # 8 hours


def db():
    DATA_DIR.mkdir(exist_ok=True)
    FILES_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    # row_factory lets rows be accessed by column name (row["username"])
    # instead of by positional index (row[0]).
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            pw_salt BLOB NOT NULL,
            pw_hash BLOB NOT NULL,
            rsa_pub_pem BLOB NOT NULL,
            sign_pub_pem BLOB NOT NULL
        )""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY(username) REFERENCES users(username)
        )""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS files (
            file_id TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            filename TEXT NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext_path TEXT NOT NULL,
            version INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            sig_b64 TEXT,
            signer TEXT,
            FOREIGN KEY(owner) REFERENCES users(username)
        )""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS file_keys (
            file_id TEXT NOT NULL,
            username TEXT NOT NULL,
            wrapped_dek BLOB NOT NULL,
            PRIMARY KEY (file_id, username),
            FOREIGN KEY(file_id) REFERENCES files(file_id),
            FOREIGN KEY(username) REFERENCES users(username)
        )""")
        conn.commit()


def now() -> int:
    return int(time.time())


def issue_token(username: str) -> str:
    # token_urlsafe(32) produces 32 random bytes encoded as URL-safe base64 (~43 chars).
    # 256 bits of entropy makes brute-force guessing infeasible.
    token = secrets.token_urlsafe(32)
    with db() as conn:
        conn.execute(
            "INSERT INTO sessions(token, username, expires_at) VALUES (?,?,?)",
            (token, username, now() + TOKEN_TTL_SECONDS)
        )
        conn.commit()
    return token


def get_auth_user() -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    with db() as conn:
        row = conn.execute(
            "SELECT username, expires_at FROM sessions WHERE token=?",
            (token,)
        ).fetchone()
    if not row:
        return None
    if row["expires_at"] < now():
        return None
    return row["username"]


def require_user() -> str:
    u = get_auth_user()
    if not u:
        abort(401)
    return u


@APP.post("/register")
def register():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    rsa_pub_pem_b64 = data.get("rsa_pub_pem_b64") or ""
    sign_pub_pem_b64 = data.get("sign_pub_pem_b64") or ""

    if not username or not password or not rsa_pub_pem_b64 or not sign_pub_pem_b64:
        return jsonify({"error": "missing fields"}), 400

    rsa_pub_pem = base64.b64decode(rsa_pub_pem_b64)
    sign_pub_pem = base64.b64decode(sign_pub_pem_b64)
    salt, pw_hash = hash_password(password)

    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO users(username, pw_salt, pw_hash, rsa_pub_pem, sign_pub_pem) VALUES (?,?,?,?,?)",
                (username, salt, pw_hash, rsa_pub_pem, sign_pub_pem)
            )
            conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "username already exists"}), 409

    return jsonify({"ok": True})


@APP.post("/login")
def login():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "missing fields"}), 400

    with db() as conn:
        row = conn.execute(
            "SELECT pw_salt, pw_hash FROM users WHERE username=?",
            (username,)
        ).fetchone()

    if not row:
        return jsonify({"error": "invalid credentials"}), 401

    if not verify_password(password, row["pw_salt"], row["pw_hash"]):
        return jsonify({"error": "invalid credentials"}), 401

    token = issue_token(username)
    return jsonify({"token": token})


@APP.get("/user_pubkeys/<username>")
def user_pubkeys(username: str):
    # public endpoint is fine for a demo; in a stronger design you might require auth
    with db() as conn:
        row = conn.execute(
            "SELECT rsa_pub_pem, sign_pub_pem FROM users WHERE username=?",
            (username,)
        ).fetchone()
    if not row:
        return jsonify({"error": "no such user"}), 404
    return jsonify({
        "rsa_pub_pem_b64": base64.b64encode(row["rsa_pub_pem"]).decode("ascii"),
        "sign_pub_pem_b64": base64.b64encode(row["sign_pub_pem"]).decode("ascii"),
    })


@APP.post("/upload")
def upload():
    """
    Web client uploads ciphertext + nonce + wrapped_dek_for_owner + ECDSA P-256 signature.
    Server verifies the signature using the uploader's registered signing public key,
    then stores ciphertext and the signature for future download verification.
    """
    user = require_user()

    data = request.json or {}
    filename = data.get("filename") or ""
    nonce_b64 = data.get("nonce_b64") or ""
    ciphertext_b64 = data.get("ciphertext_b64") or ""
    wrapped_dek_b64 = data.get("wrapped_dek_b64") or ""
    sig_b64 = data.get("sig_b64") or ""

    if not filename or not nonce_b64 or not ciphertext_b64 or not wrapped_dek_b64 or not sig_b64:
        return jsonify({"error": "missing fields"}), 400

    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    wrapped_dek = base64.b64decode(wrapped_dek_b64)
    signature = base64.b64decode(sig_b64)

    # Accept a client-provided file_id so both sides can agree on the ID before
    # the signature is verified. Fall back to a server-generated ID only if the
    # client didn't supply one (e.g. older clients).
    file_id = (data.get("file_id") or "").strip() or secrets.token_urlsafe(16)
    version = 1

    # Verify signature before persisting anything
    with db() as conn:
        row = conn.execute("SELECT sign_pub_pem FROM users WHERE username=?", (user,)).fetchone()
    if not row:
        return jsonify({"error": "user not found"}), 404

    msg = make_upload_message(file_id, nonce, ciphertext, version)
    # bytes() cast: SQLite returns a memoryview for BLOB columns; convert to plain bytes
    # before passing to the cryptography library, which requires a bytes-like object.
    if not verify_signature(msg, signature, bytes(row["sign_pub_pem"])):
        return jsonify({"error": "invalid signature"}), 403

    ct_path = FILES_DIR / f"{file_id}.bin"
    ct_path.write_bytes(ciphertext)

    with db() as conn:
        conn.execute(
            "INSERT INTO files(file_id, owner, filename, nonce, ciphertext_path, version, created_at, sig_b64, signer) VALUES (?,?,?,?,?,?,?,?,?)",
            (file_id, user, filename, nonce, str(ct_path), version, now(), sig_b64, user)
        )
        conn.execute(
            "INSERT INTO file_keys(file_id, username, wrapped_dek) VALUES (?,?,?)",
            (file_id, user, wrapped_dek)
        )
        conn.commit()

    return jsonify({"file_id": file_id, "version": version})


@APP.get("/list")
def list_files():
    user = require_user()
    with db() as conn:
        # JOIN on file_keys rather than querying files directly so that the result
        # is automatically scoped to only files this user has a wrapped DEK for
        # (i.e. files they are authorised to access).
        rows = conn.execute("""
            SELECT f.file_id, f.owner, f.filename, f.version, f.created_at,
                   f.signer AS last_modified_by
            FROM files f
            JOIN file_keys k ON k.file_id = f.file_id
            WHERE k.username=?
            ORDER BY f.created_at DESC
        """, (user,)).fetchall()

        # For each file, collect all authorised users (everyone with a file_keys row).
        # Using GROUP_CONCAT in a subquery keeps this to a single round trip.
        auth_map = {}
        if rows:
            ids = [r["file_id"] for r in rows]
            placeholders = ",".join("?" * len(ids))
            auth_rows = conn.execute(f"""
                SELECT file_id, GROUP_CONCAT(username, ',') AS users
                FROM file_keys
                WHERE file_id IN ({placeholders})
                GROUP BY file_id
            """, ids).fetchall()
            auth_map = {r["file_id"]: r["users"].split(",") if r["users"] else []
                        for r in auth_rows}

    result = []
    for r in rows:
        d = dict(r)
        all_users = auth_map.get(d["file_id"], [])
        # authorized_users = everyone except the owner
        d["authorized_users"] = [u for u in all_users if u != d["owner"]]
        result.append(d)
    return jsonify(result)


@APP.get("/download/<file_id>")
def download(file_id: str):
    user = require_user()
    with db() as conn:
        f = conn.execute("SELECT * FROM files WHERE file_id=?", (file_id,)).fetchone()
        if not f:
            return jsonify({"error": "no such file"}), 404

        k = conn.execute(
            "SELECT wrapped_dek FROM file_keys WHERE file_id=? AND username=?",
            (file_id, user)
        ).fetchone()
        if not k:
            return jsonify({"error": "no access"}), 403

    ciphertext = Path(f["ciphertext_path"]).read_bytes()
    return jsonify({
        "file_id": file_id,
        "owner": f["owner"],
        "filename": f["filename"],
        "version": f["version"],
        "nonce_b64": base64.b64encode(f["nonce"]).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "wrapped_dek_b64": base64.b64encode(k["wrapped_dek"]).decode("ascii"),
        "sig_b64": f["sig_b64"] or "",
        "signer": f["signer"] or "",
    })

@APP.post("/update")
def update():
    """
    Any user with access (not just owner) can upload a new ciphertext for a file.
    The client re-encrypts the modified plaintext with the *same* DEK they already
    hold via their wrapped_dek entry.  A fresh nonce must be provided.
    The client must also provide an ECDSA P-256 signature over the canonical upload message.
    Wrapped DEK entries for all authorised users remain unchanged (DEK is not rotated).
    Use /rotate if you want a full key rotation (owner-only).
    """
    user = require_user()
    data = request.json or {}
    file_id = data.get("file_id") or ""
    nonce_b64 = data.get("nonce_b64") or ""
    ciphertext_b64 = data.get("ciphertext_b64") or ""
    sig_b64 = data.get("sig_b64") or ""

    if not file_id or not nonce_b64 or not ciphertext_b64 or not sig_b64:
        return jsonify({"error": "missing fields"}), 400

    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    signature = base64.b64decode(sig_b64)

    with db() as conn:
        f = conn.execute("SELECT * FROM files WHERE file_id=?", (file_id,)).fetchone()
        if not f:
            return jsonify({"error": "no such file"}), 404

        # Verify the requesting user actually has access (has a wrapped DEK entry)
        k = conn.execute(
            "SELECT 1 FROM file_keys WHERE file_id=? AND username=?",
            (file_id, user)
        ).fetchone()
        if not k:
            return jsonify({"error": "no access"}), 403

        new_version = int(f["version"]) + 1

        # Verify signature before persisting
        sign_row = conn.execute("SELECT sign_pub_pem FROM users WHERE username=?", (user,)).fetchone()
        if not sign_row:
            return jsonify({"error": "user not found"}), 404

        msg = make_upload_message(file_id, nonce, ciphertext, new_version)
        if not verify_signature(msg, signature, bytes(sign_row["sign_pub_pem"])):
            return jsonify({"error": "invalid signature"}), 403

        Path(f["ciphertext_path"]).write_bytes(ciphertext)
        conn.execute(
            "UPDATE files SET nonce=?, version=?, sig_b64=?, signer=? WHERE file_id=?",
            (nonce, new_version, sig_b64, user, file_id)
        )
        conn.commit()

    return jsonify({"ok": True, "version": new_version})


@APP.get("/allowed/<file_id>")
def allowed_users(file_id: str):
    """Return current allowed users for a file (owner-only).

    Used by the UI to show a proper "<user> access has been revoked" prompt/message
    before/after a strong revoke (key rotation).
    """
    user = require_user()
    with db() as conn:
        f = conn.execute("SELECT owner FROM files WHERE file_id=?", (file_id,)).fetchone()
        if not f:
            return jsonify({"error": "no such file"}), 404
        if f["owner"] != user:
            return jsonify({"error": "only owner can view allowed users"}), 403

        rows = conn.execute(
            "SELECT username FROM file_keys WHERE file_id=? ORDER BY username ASC",
            (file_id,)
        ).fetchall()

    return jsonify({"file_id": file_id, "allowed": [r["username"] for r in rows]})

@APP.post("/grant")
def grant():
    """
    Owner grants access by uploading wrapped_dek_for_recipient.
    Server never sees DEK in plaintext.
    """
    user = require_user()
    data = request.json or {}
    file_id = data.get("file_id") or ""
    recipient = (data.get("recipient") or "").strip()
    wrapped_dek_b64 = data.get("wrapped_dek_b64") or ""
    if not file_id or not recipient or not wrapped_dek_b64:
        return jsonify({"error": "missing fields"}), 400

    wrapped_dek = base64.b64decode(wrapped_dek_b64)

    with db() as conn:
        f = conn.execute("SELECT owner FROM files WHERE file_id=?", (file_id,)).fetchone()
        if not f:
            return jsonify({"error": "no such file"}), 404
        if f["owner"] != user:
            return jsonify({"error": "only owner can grant"}), 403

        u = conn.execute("SELECT username FROM users WHERE username=?", (recipient,)).fetchone()
        if not u:
            return jsonify({"error": "no such recipient"}), 404

        # INSERT OR REPLACE handles re-granting: if the user already has a wrapped
        # DEK entry (e.g. after a previous grant), it is atomically replaced with
        # the new one rather than raising a uniqueness conflict.
        conn.execute(
            "INSERT OR REPLACE INTO file_keys(file_id, username, wrapped_dek) VALUES (?,?,?)",
            (file_id, recipient, wrapped_dek)
        )
        conn.commit()

    return jsonify({"ok": True})


@APP.post("/revoke")
def revoke():
    """
    Removes recipient's wrapped DEK entry.
    NOTE: For real revocation, owner should rotate the file key (implemented via /rotate).
    """
    user = require_user()
    data = request.json or {}
    file_id = data.get("file_id") or ""
    recipient = (data.get("recipient") or "").strip()
    if not file_id or not recipient:
        return jsonify({"error": "missing fields"}), 400

    with db() as conn:
        f = conn.execute("SELECT owner FROM files WHERE file_id=?", (file_id,)).fetchone()
        if not f:
            return jsonify({"error": "no such file"}), 404
        if f["owner"] != user:
            return jsonify({"error": "only owner can revoke"}), 403

        conn.execute("DELETE FROM file_keys WHERE file_id=? AND username=?", (file_id, recipient))
        conn.commit()

    return jsonify({"ok": True, "note": "For strong revocation, rotate the file key."})


@APP.delete("/delete/<file_id>")
def delete_file(file_id: str):
    """
    Permanently delete a file. Only the original owner may do this.
    Removes the ciphertext blob from disk, and all associated rows from
    the files and file_keys tables (cascade-style, in FK-safe order).
    """
    user = require_user()

    with db() as conn:
        f = conn.execute(
            "SELECT owner, ciphertext_path FROM files WHERE file_id=?", (file_id,)
        ).fetchone()

        if not f:
            return jsonify({"error": "no such file"}), 404

        # Only the original owner is allowed to delete
        if f["owner"] != user:
            return jsonify({"error": "only the owner can delete this file"}), 403

        ct_path = Path(f["ciphertext_path"])

        # Delete child rows first (FK constraints: file_keys references files)
        conn.execute("DELETE FROM file_keys WHERE file_id=?", (file_id,))
        conn.execute("DELETE FROM files WHERE file_id=?", (file_id,))
        conn.commit()

    # Remove the ciphertext blob from disk after DB rows are gone
    try:
        if ct_path.exists():
            ct_path.unlink()
    except OSError:
        # Non-fatal: DB rows are already deleted; log but don't fail the request
        pass

    return jsonify({"ok": True, "deleted": file_id})


@APP.post("/rotate")
def rotate():
    """
    Owner uploads a new ciphertext+nonce and a full new set of wrapped keys for allowed users.
    An ECDSA P-256 signature over the new ciphertext is required and stored.
    This gives strong revocation (re-key + re-encrypt).
    """
    user = require_user()
    data = request.json or {}
    file_id = data.get("file_id") or ""
    nonce_b64 = data.get("nonce_b64") or ""
    ciphertext_b64 = data.get("ciphertext_b64") or ""
    sig_b64 = data.get("sig_b64") or ""
    # wrapped_map: { "username": "wrapped_dek_b64", ... }
    wrapped_map = data.get("wrapped_map") or {}

    if not file_id or not nonce_b64 or not ciphertext_b64 or not sig_b64 or not isinstance(wrapped_map, dict) or not wrapped_map:
        return jsonify({"error": "missing fields"}), 400

    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    signature = base64.b64decode(sig_b64)

    with db() as conn:
        f = conn.execute("SELECT owner, ciphertext_path, version FROM files WHERE file_id=?", (file_id,)).fetchone()
        if not f:
            return jsonify({"error": "no such file"}), 404
        if f["owner"] != user:
            return jsonify({"error": "only owner can rotate"}), 403

        new_version = int(f["version"]) + 1

        # Verify signature before persisting
        sign_row = conn.execute("SELECT sign_pub_pem FROM users WHERE username=?", (user,)).fetchone()
        if not sign_row:
            return jsonify({"error": "user not found"}), 404

        msg = make_upload_message(file_id, nonce, ciphertext, new_version)
        if not verify_signature(msg, signature, bytes(sign_row["sign_pub_pem"])):
            return jsonify({"error": "invalid signature"}), 403

        Path(f["ciphertext_path"]).write_bytes(ciphertext)
        conn.execute(
            "UPDATE files SET nonce=?, version=?, sig_b64=?, signer=? WHERE file_id=?",
            (nonce, new_version, sig_b64, user, file_id)
        )
        # Delete ALL existing wrapped DEK entries for this file first, then
        # re-insert only for the allowed users supplied by the owner. This is
        # what makes rotation a strong revocation: any user not in wrapped_map
        # loses their key entry and cannot decrypt the new ciphertext.
        conn.execute("DELETE FROM file_keys WHERE file_id=?", (file_id,))

        for uname, wrapped_b64 in wrapped_map.items():
            conn.execute(
                "INSERT INTO file_keys(file_id, username, wrapped_dek) VALUES (?,?,?)",
                (file_id, uname, base64.b64decode(wrapped_b64))
            )

        # All changes (file metadata + key table replacement) committed atomically
        conn.commit()

    return jsonify({"ok": True, "version": new_version})

def clear_all_server_state():
    """
    DANGEROUS: Deletes ALL users, sessions, files metadata, wrapped keys,
    and removes all ciphertext blobs from server_data/files.
    """
    # Ensure directories exist
    DATA_DIR.mkdir(exist_ok=True)
    FILES_DIR.mkdir(parents=True, exist_ok=True)

    # Delete ciphertext blobs
    deleted_files = 0
    for p in FILES_DIR.glob("*.bin"):
        try:
            p.unlink()
            deleted_files += 1
        except Exception:
            pass

    # Delete in child-first order to satisfy foreign key constraints:
    # file_keys references both files and users; files references users;
    # sessions references users. users must be deleted last.
    with db() as conn:
        conn.execute("DELETE FROM file_keys")
        conn.execute("DELETE FROM files")
        conn.execute("DELETE FROM sessions")
        conn.execute("DELETE FROM users")
        conn.commit()

    return deleted_files

if __name__ == "__main__":
    import sys

    # Always ensure DB exists (tables created)
    init_db()

    # CLI mode: python server.py clear
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "clear":
        # Safety prompt to avoid accidental wipes
        ans = input("This will DELETE ALL server data (DB + ciphertext files). Type CLEAR to confirm: ").strip()
        if ans != "CLEAR":
            print("Aborted.")
            raise SystemExit(1)

        deleted = clear_all_server_state()
        print(f"✅ Cleared database tables and deleted {deleted} ciphertext file(s) in {FILES_DIR}")
        raise SystemExit(0)

    # Normal mode: run server
    APP.run(host="127.0.0.1", port=5000, debug=True)


