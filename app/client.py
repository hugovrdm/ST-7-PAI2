
"""Cliente BYOD: mTLS + login (RF2, RF4).
Uso:  python -m app.client --host localhost --user user001 --demo --msg "hola"
"""
import argparse
import getpass
import json
import socket
import ssl

from pki import pki_utils as u

def build_context(user: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)           # check_hostname=True
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=str(u.CA_CERT))        # valida al servidor
    ctx.load_cert_chain(u.CLIENTS / f"{user}.crt", u.CLIENTS / f"{user}.key")
    return ctx

def _rpc(f, obj: dict) -> dict:
    f.write((json.dumps(obj) + "\n").encode())
    f.flush()
    line = f.readline(65536)
    if not line:
        raise ConnectionError("el servidor cerro la conexion")
    return json.loads(line)

def session(host: str, port: int, user: str, password: str,
            msgs: list[str], verbose: bool = False) -> dict:
    ctx = build_context(user)
    raw = socket.create_connection((host, port), timeout=10)
    with ctx.wrap_socket(raw, server_hostname=host) as s:
        if verbose:
            print(f"[TLS] {s.version()} {s.cipher()[0]}")
        f = s.makefile("rwb")
        r = _rpc(f, {"cmd": "LOGIN", "user": user, "password": password})
        if not r.get("ok"):
            return {"ok": False, "error": r.get("error")}
        replies = [_rpc(f, {"cmd": "MSG", "text": m}) for m in msgs]
        _rpc(f, {"cmd": "LOGOUT"})
        try:
            s.unwrap()
        except (ssl.SSLError, OSError):
            pass
        return {"ok": True, "role": r["role"], "replies": replies}

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password")
    ap.add_argument("--demo", action="store_true",
                    help="usa la password de prueba del seed")
    ap.add_argument("--msg", action="append", default=[])
    a = ap.parse_args()

    pwd = a.password or (f"Test#2026-{a.user}" if a.demo
                         else getpass.getpass("Password: "))
    try:
        res = session(a.host, a.port, a.user, pwd, a.msg or ["ping"], verbose=True)
    except (ssl.SSLError, OSError, ConnectionError) as e:
        raise SystemExit(f"[ERROR] conexion rechazada: {e}")
    if res["ok"]:
        print(f"[OK] login como {a.user} ({res['role']})")
        for r in res["replies"]:
            print("  <-", r["echo"])
        print("[OK] sesion cerrada")
    else:
        raise SystemExit(f"[ERROR] login fallido: {res['error']}")

if __name__ == "__main__":
    main()