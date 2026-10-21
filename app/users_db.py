"""Almacen de usuarios corporativos (SQLite + scrypt)."""
import datetime as dt
import hashlib
import hmac
import os
import sqlite3
from pathlib import Path

DB = Path(__file__).resolve().parent.parent / "data" / "users.db"
ROLES = {"PDI", "PAS", "INVESTIGADOR"}

def _conn() -> sqlite3.Connection:
    DB.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        username    TEXT PRIMARY KEY,
        salt        BLOB NOT NULL,
        pwd_hash    BLOB NOT NULL,
        role        TEXT NOT NULL,
        cert_serial TEXT NOT NULL,
        created_at  TEXT NOT NULL)""")
    return c

def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt,
                          n=2**14, r=8, p=1, dklen=32)

def create_user(username: str, password: str, role: str, cert_serial: str) -> None:
    if role not in ROLES:
        raise ValueError(f"Rol invalido: {role}")
    if len(password) < 8:
        raise ValueError("Password demasiado corta (minimo 8)")
    salt = os.urandom(16)
    conn = _conn()
    try:
        with conn:
            conn.execute("INSERT INTO users VALUES (?,?,?,?,?,?)",
                         (username, salt, _hash(password, salt), role,
                          cert_serial, dt.datetime.now(dt.timezone.utc).isoformat()))
    except sqlite3.IntegrityError:
        raise ValueError(f"El usuario '{username}' ya existe") from None
    finally:
        conn.close()

def verify(username: str, password: str) -> dict | None:
    """Devuelve {'role','cert_serial'} si las credenciales son correctas."""
    conn = _conn()
    try:
        row = conn.execute("SELECT salt, pwd_hash, role, cert_serial "
                           "FROM users WHERE username=?", (username,)).fetchone()
    finally:
        conn.close()
    salt = row[0] if row else b"\x00" * 16      # mismo coste si el usuario no existe
    h = _hash(password, salt)
    if row and hmac.compare_digest(h, row[1]):
        return {"role": row[2], "cert_serial": row[3]}
    return None

def exists(username: str) -> bool:
    conn = _conn()
    try:
        return conn.execute("SELECT 1 FROM users WHERE username=?",
                            (username,)).fetchone() is not None
    finally:
        conn.close()