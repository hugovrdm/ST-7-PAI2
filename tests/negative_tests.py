"""Pruebas negativas de seguridad (RS1, RS2) contra el servidor en marcha.
Uso (desde la raiz, con el .venv activo):
    python -m tests.negative_tests --host localhost
"""
import argparse
import datetime as dt
import socket
import ssl
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from pki import pki_utils as u

TLS12, TLS13 = ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3

def make_ctx(version, cert=None, trust_ca=True):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.minimum_version = c.maximum_version = version
    if trust_ca:
        c.load_verify_locations(cafile=str(u.CA_CERT))
    else:
        c.load_default_certs()
    if cert:
        c.load_cert_chain(*cert)
    return c

def attempt(host, port, ctx) -> str:
    try:
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                s.sendall(b'{"cmd":"LOGOUT"}\n')
                data = s.recv(1024)          # en TLS 1.3 el rechazo llega aqui
                if not data:
                    return "RECHAZADO: conexion cerrada sin datos"
                return f"CONECTADO ({s.version()})"
    except (ssl.SSLError, OSError) as e:
        return f"RECHAZADO: {e}"

def self_signed(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    name = u.subject_name(cn)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(u.now() - dt.timedelta(minutes=1))
            .not_valid_after(u.now() + dt.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    d = Path(tempfile.mkdtemp())
    u.save_key(key, d / "k.pem")
    u.save_cert(cert, d / "c.pem")
    return str(d / "c.pem"), str(d / "k.pem")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--user", default="user003")
    a = ap.parse_args()
    ok_cert = (str(u.CLIENTS / f"{a.user}.crt"), str(u.CLIENTS / f"{a.user}.key"))

    casos = [
        ("Control positivo: cert valido + TLS 1.3",        make_ctx(TLS13, ok_cert), True),
        ("Sin certificado de cliente (mTLS)",              make_ctx(TLS13), False),
        ("Certificado autofirmado (suplantacion)",         make_ctx(TLS13, self_signed(a.user)), False),
        ("Solo TLS 1.2 con cert valido (downgrade)",       make_ctx(TLS12, ok_cert), False),
        ("Cliente que no confia en la CA (valida server)", make_ctx(TLS13, ok_cert, trust_ca=False), False),
    ]
    fallos = 0
    for nombre, ctx, debe_conectar in casos:
        res = attempt(a.host, a.port, ctx)
        ok = res.startswith("CONECTADO") == debe_conectar
        fallos += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {nombre}\n       -> {res}")
    raise SystemExit(1 if fallos else 0)

if __name__ == "__main__":
    main()