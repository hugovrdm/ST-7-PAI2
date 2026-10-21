"""Re-emision de certificado (RF1): revoca el activo y emite uno nuevo.
Uso: python -m app.reissue_user --user nuevo01
"""
import argparse

from app import users_db
from pki import pki_utils as u
from pki.issue_cert import issue_client_bundle
from pki.revoke import revoke

def reissue(user: str) -> str:
    info = users_db.get(user)
    if not info:
        raise SystemExit(f"[ERROR] el usuario '{user}' no existe")
    old = u.active_client_cert(user)
    if old:
        revoke(user=user)                          # revoca y regenera la CRL
    issue_client_bundle(user, info["role"])
    new = u.active_client_cert(user)["serial"]
    users_db.update_serial(user, new)
    print(f"[OK] {user}: viejo={info['cert_serial'][:12]} nuevo={new[:12]}")
    return new

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    reissue(ap.parse_args().user)