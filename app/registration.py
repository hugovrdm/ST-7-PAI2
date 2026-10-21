"""Logica de alta de usuarios BYOD (RF1)."""
import hmac
import os
import re
import threading

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app import users_db
from pki.issue_cert import ROLES, sign_client_csr
from pki.revoke import revoke

USER_RE = re.compile(r"^[a-z][a-z0-9_.-]{2,31}$")
MIN_PWD = 10
_LOCK = threading.Lock()          # evita carreras sobre index.json

def _err(code: str) -> dict:
    return {"ok": False, "error": code}

def _token_ok(given) -> bool:
    expected = os.environ.get("PKI_ENROLL_TOKEN", "")
    return bool(expected) and hmac.compare_digest(str(given).encode(), expected.encode())

def register(req: dict) -> dict:
    user = str(req.get("user", ""))
    password = str(req.get("password", ""))
    role = str(req.get("role", ""))

    if not _token_ok(req.get("token", "")):
        return _err("bad_token")
    if not USER_RE.match(user):
        return _err("bad_username")
    if role not in ROLES:
        return _err("bad_role")
    if len(password) < MIN_PWD:
        return _err("weak_password")
    try:
        csr = x509.load_pem_x509_csr(str(req.get("csr", "")).encode())
    except ValueError:
        return _err("bad_csr")

    with _LOCK:
        if users_db.exists(user):
            return _err("user_exists")            # inmutabilidad (RF1)
        try:
            cert = sign_client_csr(csr, user, role)
        except ValueError:
            return _err("csr_rejected")
        serial = format(cert.serial_number, "x")
        try:
            users_db.create_user(user, password, role, serial)
        except Exception:
            revoke(serial=serial)                 # no dejar certificados huerfanos
            return _err("internal")
    return {"ok": True, "role": role,
            "cert": cert.public_bytes(serialization.Encoding.PEM).decode()}