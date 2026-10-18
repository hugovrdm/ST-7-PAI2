"""Revocacion de certificados y generacion de la CRL.

Uso:
    python -m pki.revoke --user alice      # revoca el cert activo de alice
    python -m pki.revoke --serial 1a2b3c   # revoca por numero de serie (hex)
    python -m pki.revoke --list            # lista certificados emitidos
    python -m pki.revoke --regen           # regenera la CRL (caduca a los 7 dias)
"""
import argparse

from pki import pki_utils as u


def revoke(user: str | None = None, serial: str | None = None) -> str:
    index = u.load_index()
    for e in index["certs"]:
        match = e["serial"].startswith(serial.lower()) if serial else \
            (e["cn"] == user and e["kind"] == "client")
        if match and e["status"] == "active":
            e["status"] = "revoked"
            e["revoked_at"] = u.now().isoformat()
            u.save_index(index)
            u.build_crl()
            return e["serial"]
    raise ValueError("No hay ningun certificado activo que coincida")


def list_certs() -> None:
    for e in u.load_index()["certs"]:
        print(f"{e['serial']:<40} {e['kind']:<7} {e['cn']:<20} "
            f"{str(e['role']):<13} {e['status']}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--user")
    ap.add_argument("--serial")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--regen", action="store_true")
    a = ap.parse_args()

    if a.list:
        list_certs()
    elif a.regen:
        u.build_crl()
        print(f"[OK] CRL regenerada: {u.CRL_FILE}")
    elif a.user or a.serial:
        s = revoke(a.user, a.serial)
        print(f"[OK] Revocado serial={s}. CRL actualizada.")
    else:
        ap.error("indica --user, --serial, --list o --regen")