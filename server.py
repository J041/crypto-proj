import base64
import os
import sqlite3
import secrets
import time
from pathlib import Path
from typing import Optional

from flask import Flask, request, jsonify, send_file, abort

from crypto_utils import hash_password, verify_password

APP = Flask(__name__)

DATA_DIR = Path("server_data")
DB_PATH = DATA_DIR / "server.db"
FILES_DIR = DATA_DIR / "files"
TOKEN_TTL_SECONDS = 60 * 60 * 8  # 8 hours


def db():
    DATA_DIR.mkdir(exist_ok=True)
    FILES_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
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
    Client uploads ciphertext + nonce + wrapped_dek_for_owner.
    Server stores ciphertext only.
    """
    user = require_user()

    data = request.json or {}
    filename = data.get("filename") or ""
    nonce_b64 = data.get("nonce_b64") or ""
    ciphertext_b64 = data.get("ciphertext_b64") or ""
    wrapped_dek_b64 = data.get("wrapped_dek_b64") or ""

    if not filename or not nonce_b64 or not ciphertext_b64 or not wrapped_dek_b64:
        return jsonify({"error": "missing fields"}), 400

    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    wrapped_dek = base64.b64decode(wrapped_dek_b64)

    file_id = secrets.token_urlsafe(16)
    ct_path = FILES_DIR / f"{file_id}.bin"
    ct_path.write_bytes(ciphertext)

    with db() as conn:
        conn.execute(
            "INSERT INTO files(file_id, owner, filename, nonce, ciphertext_path, version, created_at) VALUES (?,?,?,?,?,?,?)",
            (file_id, user, filename, nonce, str(ct_path), 1, now())
        )
        conn.execute(
            "INSERT INTO file_keys(file_id, username, wrapped_dek) VALUES (?,?,?)",
            (file_id, user, wrapped_dek)
        )
        conn.commit()

    return jsonify({"file_id": file_id, "version": 1})


@APP.get("/list")
def list_files():
    user = require_user()
    with db() as conn:
        rows = conn.execute("""
            SELECT f.file_id, f.owner, f.filename, f.version, f.created_at
            FROM files f
            JOIN file_keys k ON k.file_id = f.file_id
            WHERE k.username=?
            ORDER BY f.created_at DESC
        """, (user,)).fetchall()

    return jsonify([dict(r) for r in rows])


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
    })


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


@APP.post("/rotate")
def rotate():
    """
    Owner uploads a new ciphertext+nonce and a full new set of wrapped keys for allowed users.
    This gives strong revocation (re-key + re-encrypt).
    """
    user = require_user()
    data = request.json or {}
    file_id = data.get("file_id") or ""
    nonce_b64 = data.get("nonce_b64") or ""
    ciphertext_b64 = data.get("ciphertext_b64") or ""
    # wrapped_map: { "username": "wrapped_dek_b64", ... }
    wrapped_map = data.get("wrapped_map") or {}

    if not file_id or not nonce_b64 or not ciphertext_b64 or not isinstance(wrapped_map, dict) or not wrapped_map:
        return jsonify({"error": "missing fields"}), 400

    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    with db() as conn:
        f = conn.execute("SELECT owner, ciphertext_path, version FROM files WHERE file_id=?", (file_id,)).fetchone()
        if not f:
            return jsonify({"error": "no such file"}), 404
        if f["owner"] != user:
            return jsonify({"error": "only owner can rotate"}), 403

        Path(f["ciphertext_path"]).write_bytes(ciphertext)
        new_version = int(f["version"]) + 1

        conn.execute("UPDATE files SET nonce=?, version=? WHERE file_id=?", (nonce, new_version, file_id))
        conn.execute("DELETE FROM file_keys WHERE file_id=?", (file_id,))

        for uname, wrapped_b64 in wrapped_map.items():
            conn.execute(
                "INSERT INTO file_keys(file_id, username, wrapped_dek) VALUES (?,?,?)",
                (file_id, uname, base64.b64decode(wrapped_b64))
            )

        conn.commit()

    return jsonify({"ok": True, "version": new_version})


if __name__ == "__main__":
    init_db()
    APP.run(host="127.0.0.1", port=5000, debug=True)
