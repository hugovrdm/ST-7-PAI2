"""Pruebas funcionales RF1, RF2 y RF4 contra el servidor en marcha.
Uso: python -m tests.functional_tests --host vpn.u-secure.es
"""
import argparse
import os
import secrets
import socket
import ssl

from app.client import _rpc, _talk, build_context
from app.register import register
from pki import pki_utils as u

def _connect(host, port, cert_user):
    ctx = build_context(cert_user)
    return ctx.wrap_socket(socket.create_connection((host, port), timeout=10),
                           server_hostname=host)

def login(host, port, cert_user, user, password) -> dict:
    with _connect(host, port, cert_user) as s:
        return _talk(s, user, password, ["ping"])

def usable_after_logout(host, port, user, password) -> bool:
    with _connect(host, port, user) as s:
        f = s.makefile("rwb")
        _rpc(f, {"cmd": "LOGIN", "user": user, "password": password})
        _rpc(f, {"cmd": "LOGOUT"})
        try:
            _rpc(f, {"cmd": "MSG", "text": "x"})
            return True
        except (ConnectionError, OSError, ssl.SSLError, ValueError):
            return False

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="vpn.u-secure.es")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--reg-port", type=int, default=8444)
    a = ap.parse_args()

    token = os.environ.get("PKI_ENROLL_TOKEN", "")
    new, pwd = "test_" + secrets.token_hex(3), "Clave#Segura-2026"
    reg = lambda **kw: register(a.host, a.reg_port,
                                **{**dict(user=new, password=pwd, role="PDI", token=token), **kw})
    fallos = 0

    def check(nombre, cond, detalle=""):
        nonlocal fallos
        fallos += not cond
        print(f"[{'PASS' if cond else 'FAIL'}] {nombre} {detalle}")

    r = reg()
    check("RF1 alta correcta con CSR", r.get("ok"), str(r.get("error", "")))
    check("RF1 clave y certificado guardados en el dispositivo",
          (u.CLIENTS / f"{new}.key").exists() and (u.CLIENTS / f"{new}.crt").exists())
    check("RF1 inmutabilidad: re-registro rechazado", reg().get("error") == "user_exists")
    check("RF1 codigo de alta incorrecto", reg(user=new + "x", token="mal").get("error") == "bad_token")
    check("RF1 nombre de usuario invalido", reg(user="Mal Usuario").get("error") == "bad_username")
    check("RF1 rol invalido", reg(user=new + "y", role="ADMIN").get("error") == "bad_role")
    check("RF1 contrasena debil", reg(user=new + "z", password="corta").get("error") == "weak_password")

    check("RF2 login correcto (cert + password)", login(a.host, a.port, new, new, pwd).get("ok"))
    check("RF2 password incorrecta", not login(a.host, a.port, new, new, "Mala#Clave-1").get("ok"))
    check("RF2 cert propio con identidad ajena (user003)",
          not login(a.host, a.port, new, "user003", "Test#2026-user003").get("ok"))
    check("RF4 sesion inutilizable tras LOGOUT", not usable_after_logout(a.host, a.port, new, pwd))
    raise SystemExit(1 if fallos else 0)

if __name__ == "__main__":
    main()