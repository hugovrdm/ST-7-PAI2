"""Precarga usuarios corporativos + certificados (RF5 / RS3).
Uso (desde pai2/):  python -m app.seed_users --n 300
"""
import argparse
from itertools import cycle

from pki import pki_utils as u
from pki.issue_cert import issue_client_bundle
from app import users_db

ROLES = ["PDI", "PAS", "INVESTIGADOR"]

def seed(n: int) -> None:
    nuevos = 0
    for i, role in zip(range(1, n + 1), cycle(ROLES)):
        name = f"user{i:03d}"
        if users_db.exists(name):
            continue                      # ya precargado: no tocar
        try:
            issue_client_bundle(name, role)
        except ValueError:
            continue                      # ya tenia certificado activo
        serial = u.active_client_cert(name)["serial"]
        users_db.create_user(name, f"Test#2026-{name}", role, serial)
        nuevos += 1
    print(f"[OK] {nuevos} usuarios nuevos (total solicitado: {n})")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=300)
    seed(ap.parse_args().n)

                    # ya precargado: no tocar