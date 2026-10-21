"""Servidor TLS 1.3 + mTLS (RF2, RF4, RS1-RS4).
Uso (desde pai2/):  python -m app.server --host 0.0.0.0 --port 8443
"""
import argparse
import functools
import json
import logging
import os
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

from app import registration, users_db
from pki import pki_utils as u

ALLOWED_CIPHERS = {"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}
MAX_LINE = 4096
MAX_REG_LINE = 16384
HANDSHAKE_TIMEOUT = 10
IDLE_TIMEOUT = 60
MAX_ATTEMPTS = 3
LOG_FILE = Path(__file__).resolve().parent.parent / "logs" / "audit.log"

# --- Auditoria ------------------------------------------------------------
def setup_audit() -> logging.Logger:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    log = logging.getLogger("audit")
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s | %(message)s")
    for h in (logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler()):
        h.setFormatter(fmt)
        log.addHandler(h)
    return log

audit = setup_audit()

# --- Contexto TLS ---------------------------------------------------------
def build_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(u.STORE / "server.crt", u.STORE / "server.key")
    ctx.verify_mode = ssl.CERT_REQUIRED                     # mTLS
    ctx.load_verify_locations(cafile=str(u.CA_CERT))
    ctx.load_verify_locations(cafile=str(u.CRL_FILE))      # CRL
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    return ctx

def check_crl_fresh() -> None:
    crl = x509.load_pem_x509_crl(u.CRL_FILE.read_bytes())
    if crl.next_update_utc < u.now():
        raise SystemExit("CRL caducada: ejecuta  python -m pki.revoke --regen")

_ctx = build_context()

def build_reg_context() -> ssl.SSLContext:
    """Puerto de alta: TLS 1.3, el servidor se autentica; el cliente aun no tiene cert."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(u.STORE / "server.crt", u.STORE / "server.key")
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

_reg_ctx = build_reg_context()

def watch_crl() -> None:
    """Recarga el contexto TLS cuando cambia la CRL (revocacion en caliente)."""
    global _ctx
    last = u.CRL_FILE.stat().st_mtime
    while True:
        time.sleep(10)
        try:
            m = u.CRL_FILE.stat().st_mtime
            if m != last:
                _ctx = build_context()
                last = m
                audit.info("CRL_RELOADED")
        except Exception as e:
            audit.error("CRL_RELOAD_FAIL reason=%s", e)

# --- Sesion ---------------------------------------------------------------
_active = 0
_lock = threading.Lock()

def _count(delta: int) -> int:
    global _active
    with _lock:
        _active += delta
        return _active

def _close(ssock: ssl.SSLSocket) -> None:
    """Cierre TLS limpio (close_notify) -> claves de sesion descartadas (RF4)."""
    try:
        ssock.settimeout(2)
        ssock.unwrap().close()
    except Exception:
        ssock.close()

def handle(raw: socket.socket, addr, plain: bool = False) -> None:
    peer = f"{addr[0]}:{addr[1]}"
    if plain:                       # SOLO BENCHMARK: canal sin cifrar
        ssock, cn, serial, version, cipher = raw, None, None, "PLAIN", "none"
    else:
        raw.settimeout(HANDSHAKE_TIMEOUT)
        try:
            ssock = _ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError) as e:
            audit.warning("TLS_FAIL peer=%s reason=%s", peer, e)
            raw.close()
            return
        try:
            cert = x509.load_der_x509_certificate(ssock.getpeercert(binary_form=True))
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            serial = format(cert.serial_number, "x")
            version, cipher = ssock.version(), ssock.cipher()[0]
        except Exception as e:
            audit.warning("TLS_FAIL peer=%s reason=cert_parse:%s", peer, e)
            _close(ssock)
            return
        if version != "TLSv1.3" or cipher not in ALLOWED_CIPHERS:
            audit.warning("CIPHER_REJECTED peer=%s version=%s cipher=%s", peer, version, cipher)
            _close(ssock)
            return
        
    n = _count(+1)
    audit.info("CONNECT peer=%s cert_cn=%s serial=%s %s %s active=%d",
               peer, cn, (serial or "-")[:12], version, cipher, n)
    t0 = time.time()
    user, attempts, reason = None, 0, "peer_closed"
    ssock.settimeout(IDLE_TIMEOUT)
    f = ssock.makefile("rwb")

    def send(obj: dict) -> None:
        f.write((json.dumps(obj) + "\n").encode())
        f.flush()

    try:
        while True:
            line = f.readline(MAX_LINE + 1)
            if not line:
                break
            if len(line) > MAX_LINE:
                send({"ok": False, "error": "too_long"})
                reason = "too_long"
                break
            try:
                req = json.loads(line)
                if not isinstance(req, dict):
                    raise ValueError
            except ValueError:
                send({"ok": False, "error": "bad_request"})
                continue

            cmd = req.get("cmd")
            if cmd == "LOGIN" and user is None:
                name = str(req.get("user", ""))[:64]
                info = users_db.verify(name, str(req.get("password", "")))
                if info and (plain or (name == cn and info["cert_serial"] == serial)):
                    user = name
                    audit.info("LOGIN_OK user=%s role=%s peer=%s", user, info["role"], peer)
                    send({"ok": True, "role": info["role"]})
                else:
                    attempts += 1
                    motivo = "bad_credentials" if not info else "identity_mismatch"
                    audit.warning("LOGIN_FAIL user=%r cert_cn=%s peer=%s attempt=%d reason=%s",
              name, cn, peer, attempts, motivo)
                    send({"ok": False, "error": "auth_failed"})
                    if attempts >= MAX_ATTEMPTS:
                        reason = "too_many_attempts"
                        break
            elif cmd == "MSG" and user:
                text = str(req.get("text", ""))[:1000]
                send({"ok": True, "echo": text, "len": len(text)})
            elif cmd == "LOGOUT":
                send({"ok": True, "bye": True})
                reason = "logout"
                break
            else:
                send({"ok": False, "error": "not_allowed"})
    except (OSError, ssl.SSLError) as e:
        reason = f"error:{type(e).__name__}"
    finally:
        audit.info("DISCONNECT peer=%s user=%s reason=%s duration=%.2fs active=%d",
                   peer, user, reason, time.time() - t0, _count(-1))
        try:
            f.close()
        except Exception:
            pass
        _close(ssock)

def handle_register(raw: socket.socket, addr) -> None:
    peer = f"{addr[0]}:{addr[1]}"
    raw.settimeout(HANDSHAKE_TIMEOUT)
    try:
        ssock = _reg_ctx.wrap_socket(raw, server_side=True)
    except (ssl.SSLError, OSError) as e:
        audit.warning("REG_TLS_FAIL peer=%s reason=%s", peer, e)
        raw.close()
        return
    user, res = "", {"ok": False, "error": "bad_request"}
    try:
        ssock.settimeout(15)
        f = ssock.makefile("rwb")
        line = f.readline(MAX_REG_LINE + 1)
        if line and len(line) <= MAX_REG_LINE:
            try:
                req = json.loads(line)
            except ValueError:
                req = None
            if isinstance(req, dict) and req.get("cmd") == "REGISTER":
                user = str(req.get("user", ""))[:64]
                try:
                    res = registration.register(req)
                except Exception as e:
                    audit.error("REG_INTERNAL peer=%s reason=%s", peer, type(e).__name__)
                    res = {"ok": False, "error": "internal"}
        level = logging.INFO if res["ok"] else logging.WARNING
        audit.log(level, "REGISTER_%s user=%r peer=%s %s",
                  "OK" if res["ok"] else "FAIL", user, peer, res.get("error", ""))
        f.write((json.dumps(res) + "\n").encode())
        f.flush()
    except (OSError, ssl.SSLError) as e:
        audit.warning("REG_ERROR peer=%s reason=%s", peer, e)
    finally:
        _close(ssock)


# --- Main -------------------------------------------------------------------
def serve(host: str, port: int, pool: ThreadPoolExecutor, fn) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(512)
    while True:
        conn, addr = srv.accept()
        pool.submit(fn, conn, addr)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--plain-port", type=int, default=0,
                    help="puerto SIN CIFRAR, solo benchmark/comparativa")
    ap.add_argument("--reg-port", type=int, default=0,
                    help="puerto de alta de usuarios (TLS 1.3, sin mTLS)")
    ap.add_argument("--workers", type=int, default=400)
    a = ap.parse_args()

    check_crl_fresh()
    if a.reg_port and not os.environ.get("PKI_ENROLL_TOKEN"):
        raise SystemExit("Falta PKI_ENROLL_TOKEN: el registro queda deshabilitado")
    threading.Thread(target=watch_crl, daemon=True).start()
    pool = ThreadPoolExecutor(max_workers=a.workers)
    audit.info("SERVER_START host=%s port=%d workers=%d", a.host, a.port, a.workers)
    if a.plain_port:
        threading.Thread(target=serve, daemon=True,
                         args=(a.host, a.plain_port, pool, functools.partial(handle, plain=True))).start()
        audit.warning("PLAIN_LISTENER port=%d (SIN CIFRAR, SOLO BENCHMARK)", a.plain_port)
    if a.reg_port:
        threading.Thread(target=serve, daemon=True,
                         args=(a.host, a.reg_port, pool, handle_register)).start()
        audit.info("REG_LISTENER port=%d", a.reg_port)
    try:
        serve(a.host, a.port, pool, handle)
    except KeyboardInterrupt:
        audit.info("SERVER_STOP")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

if __name__ == "__main__":
    main()