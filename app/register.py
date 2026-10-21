"""Alta de usuario desde el dispositivo BYOD (RF1).
Uso: python -m app.register --host vpn.u-secure.es --user nuevo01 --role PDI
"""
import argparse
import getpass
import json
import os
import socket
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from pki import pki_utils as u
from pki.issue_cert import ROLES, make_csr

def register(host: str, port: int, user: str, password: str, role: str,
             token: str, out_dir: Path = u.CLIENTS) -> dict:
    key = u.new_key()                                   # la clave NO sale del dispositivo
    csr_pem = make_csr(key, user).public_bytes(serialization.Encoding.PEM).decode()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=str(u.CA_CERT))    # valida al servidor
    with socket.create_connection((host, port), timeout=15) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            f = s.makefile("rwb")
            f.write((json.dumps({"cmd": "REGISTER", "user": user, "password": password,
                                 "role": role, "token": token, "csr": csr_pem}) + "\n").encode())
            f.flush()
            line = f.readline(65536)
    res = json.loads(line) if line else {"ok": False, "error": "no_response"}
    if res.get("ok"):
        cert = x509.load_pem_x509_certificate(res["cert"].encode())
        if cert.public_key().public_numbers() != key.public_key().public_numbers():
            return {"ok": False, "error": "cert_key_mismatch"}
        out_dir.mkdir(parents=True, exist_ok=True)
        u.save_key(key, out_dir / f"{user}.key")
        (out_dir / f"{user}.crt").write_text(res["cert"])
    return res

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=8444)
    ap.add_argument("--user", required=True)
    ap.add_argument("--role", required=True, choices=sorted(ROLES))
    ap.add_argument("--password")
    ap.add_argument("--token")
    a = ap.parse_args()
    pwd = a.password or getpass.getpass("Password (min. 10): ")
    token = a.token or os.environ.get("PKI_ENROLL_TOKEN") or getpass.getpass("Codigo de alta: ")
    try:
        res = register(a.host, a.port, a.user, pwd, a.role, token)
    except (ssl.SSLError, OSError) as e:
        raise SystemExit(f"[ERROR] {e}")
    if not res.get("ok"):
        raise SystemExit(f"[ERROR] registro rechazado: {res.get('error')}")
    print(f"[OK] '{a.user}' registrado ({res['role']}). Clave y certificado en {u.CLIENTS}")

if __name__ == "__main__":
    main()