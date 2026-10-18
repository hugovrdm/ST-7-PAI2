"""Utilidades comunes de la PKI corporativa U-Secure."""
import datetime as dt
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# --- Rutas -------------------------------------------------------------
STORE = Path(__file__).parent / "store"
CLIENTS = STORE / "clients"
CA_CERT = STORE / "ca.crt"
CA_KEY = STORE / "ca.key"
CRL_FILE = STORE / "crl.pem"
INDEX_FILE = STORE / "index.json"

ORG = "U-Secure University"
COUNTRY = "ES"
CA_CN = "U-Secure Root CA"
SIG_HASH = hashes.SHA384()


# --- Tiempo / claves ---------------------------------------------------
def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def new_key() -> ec.EllipticCurvePrivateKey:
    """ECDSA P-256: rapido y adecuado para TLS 1.3."""
    return ec.generate_private_key(ec.SECP256R1())


def ca_password() -> bytes | None:
    """Password de la clave de la CA (variable de entorno PKI_CA_PASSWORD)."""
    pwd = os.environ.get("PKI_CA_PASSWORD")
    return pwd.encode() if pwd else None


def save_key(key, path: Path, password: bytes | None = None) -> None:
    enc = (serialization.BestAvailableEncryption(password)
           if password else serialization.NoEncryption())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        enc))
    try:
        os.chmod(path, 0o600)  # sin efecto en Windows
    except OSError:
        pass


def save_cert(cert: x509.Certificate, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def load_ca():
    """Devuelve (certificado, clave privada) de la CA."""
    cert = x509.load_pem_x509_certificate(CA_CERT.read_bytes())
    key = serialization.load_pem_private_key(CA_KEY.read_bytes(), ca_password())
    return cert, key


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def subject_name(cn: str, ou: str | None = None) -> x509.Name:
    attrs = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
    ]
    if ou:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(attrs)


# --- Indice de certificados emitidos ----------------------------------
def load_index() -> dict:
    if INDEX_FILE.exists():
        return json.loads(INDEX_FILE.read_text(encoding="utf-8"))
    return {"certs": []}


def save_index(index: dict) -> None:
    """Escritura atómica: evita dejar index.json corrupto si algo falla."""
    INDEX_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = INDEX_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(index, indent=2), encoding="utf-8")
    os.replace(tmp, INDEX_FILE)

def register_cert(cert: x509.Certificate, cn: str, kind: str, role: str | None = None) -> None:
    index = load_index()
    index["certs"].append({
        "serial": format(cert.serial_number, "x"),
        "cn": cn,
        "kind": kind,                      # "server" | "client"
        "role": role,                      # PDI | PAS | INVESTIGADOR
        "sha256": fingerprint(cert),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "status": "active",                # active | revoked
        "revoked_at": None,
    })
    save_index(index)


def active_client_cert(cn: str) -> dict | None:
    """Certificado de cliente activo Y no caducado."""
    for entry in load_index()["certs"]:
        if (entry["kind"] == "client" and entry["cn"] == cn
                and entry["status"] == "active"
                and dt.datetime.fromisoformat(entry["not_after"]) > now()):
            return entry
    return None


# --- CRL ----------------------------------------------------------------
def build_crl(valid_days: int = 7) -> x509.CertificateRevocationList:
    """Regenera la CRL a partir del indice y la guarda en store/crl.pem."""
    ca_cert, ca_key = load_ca()
    builder = (x509.CertificateRevocationListBuilder()
               .issuer_name(ca_cert.subject)
               .last_update(now() - dt.timedelta(minutes=1))
               .next_update(now() + dt.timedelta(days=valid_days)))
    for e in load_index()["certs"]:
        if e["status"] == "revoked":
            revoked = (x509.RevokedCertificateBuilder()
                       .serial_number(int(e["serial"], 16))
                       .revocation_date(dt.datetime.fromisoformat(e["revoked_at"]))
                       .build())
            builder = builder.add_revoked_certificate(revoked)
    crl = builder.sign(ca_key, SIG_HASH)
    CRL_FILE.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    return crl