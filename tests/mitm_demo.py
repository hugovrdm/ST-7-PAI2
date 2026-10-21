"""Demostracion de ataques de interceptacion (extra, Obj.5).
Uso: docker compose run --rm --no-deps client python -m tests.mitm_demo --host vpn.u-secure.es
"""
import argparse
import datetime as dt
import socket
import ssl
import tempfile
import threading
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from app.client import _talk, build_context
from pki import pki_utils as u

USER, PWD, SECRET = "user010", "Test#2026-user010", "secreto-mitm"

def fake_cert(host):
    key = ec.generate_private_key(ec.SECP256R1())
    name = u.subject_name(host)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(u.now() - dt.timedelta(minutes=1))
            .not_valid_after(u.now() + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .sign(key, hashes.SHA256()))
    d = Path(tempfile.mkdtemp())
    u.save_key(key, d / "k.pem")
    u.save_cert(cert, d / "c.pem")
    return str(d / "c.pem"), str(d / "k.pem")

def _listener(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(1)
    return s

def mitm_fake_cert(host):
    """El atacante se hace pasar por el servidor con un certificado que no es de la CA."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*fake_cert(host))
    srv = _listener(18441)
    def attacker():
        conn, _ = srv.accept()
        try:
            ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            pass
        finally:
            conn.close()
    threading.Thread(target=attacker, daemon=True).start()
    try:
        with socket.create_connection(("127.0.0.1", 18441), timeout=10) as raw:
            build_context(USER).wrap_socket(raw, server_hostname=host)
        return False, "el cliente ACEPTO el certificado falso"
    except ssl.SSLError as e:
        return "CERTIFICATE_VERIFY_FAILED" in str(e), str(e)

def start_relay(port, target, tamper):
    """Proxy TCP entre cliente y servidor real; opcionalmente altera un bit en transito."""
    srv = _listener(port)
    captured, st = [], {"last": time.time(), "done": False}
    def serve():
        cli, _ = srv.accept()
        up = socket.create_connection(target, timeout=10)
        def pump(src, dst, direction):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    if (tamper and direction == "c2s" and not st["done"] and len(data) > 6
                            and time.time() - st["last"] > 0.25):
                        i = len(data) // 2
                        data = data[:i] + bytes([data[i] ^ 0x01]) + data[i + 1:]
                        st["done"] = True
                    st["last"] = time.time()
                    captured.append(data)
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
        threading.Thread(target=pump, args=(cli, up, "c2s"), daemon=True).start()
        threading.Thread(target=pump, args=(up, cli, "s2c"), daemon=True).start()
    threading.Thread(target=serve, daemon=True).start()
    return captured, st

def mitm_passive(host, target):
    cap, _ = start_relay(18442, target, tamper=False)
    with socket.create_connection(("127.0.0.1", 18442), timeout=10) as raw:
        with build_context(USER).wrap_socket(raw, server_hostname=host) as s:
            res = _talk(s, USER, PWD, [SECRET])
    time.sleep(0.3)
    blob = b"".join(cap)
    visible = SECRET.encode() in blob or PWD.encode() in blob
    return (bool(res.get("ok")) and not visible,
            f"sesion_ok={res.get('ok')} bytes_capturados={len(blob)} "
            f"secreto_visible={visible} inicio={blob[:24].hex()}")

def mitm_tamper(host, target):
    cap, st = start_relay(18443, target, tamper=True)
    try:
        with socket.create_connection(("127.0.0.1", 18443), timeout=10) as raw:
            with build_context(USER).wrap_socket(raw, server_hostname=host) as s:
                time.sleep(0.6)               # hueco para que el proxy altere el siguiente registro
                res = _talk(s, USER, PWD, [SECRET])
        return False, f"la alteracion NO se detecto (res={res})"
    except (ssl.SSLError, OSError, ConnectionError) as e:
        return st["done"], f"alteracion_realizada={st['done']}; sesion abortada: {type(e).__name__}: {e}"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="vpn.u-secure.es")
    ap.add_argument("--port", type=int, default=8443)
    a = ap.parse_args()
    target = (a.host, a.port)
    casos = [
        ("MITM activo con certificado falso: el cliente debe rechazarlo", mitm_fake_cert(a.host)),
        ("Interceptacion pasiva: la sesion funciona y no se ve el secreto", mitm_passive(a.host, target)),
        ("Alteracion de un bit en transito: la sesion debe abortar", mitm_tamper(a.host, target)),
    ]
    fallos = 0
    for nombre, (ok, detalle) in casos:
        fallos += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {nombre}\n       -> {detalle}")
    raise SystemExit(1 if fallos else 0)

if __name__ == "__main__":
    main()