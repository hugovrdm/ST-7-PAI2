import argparse
import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from pki import pki_utils as u

ROLES = {"PDI", "PAS", "INVESTIGADOR"}


def _build(subject, public_key, ca_cert, ca_key, eku, san, days) -> x509.Certificate:
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(ca_cert.subject)
               .public_key(public_key)
               .serial_number(x509.random_serial_number())
               .not_valid_before(u.now() - dt.timedelta(minutes=1))
               .not_valid_after(u.now() + dt.timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(
                   digital_signature=True, content_commitment=False,
                   key_encipherment=False, data_encipherment=False,
                   key_agreement=False, key_cert_sign=False, crl_sign=False,
                   encipher_only=False, decipher_only=False), critical=True)
               .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
               .add_extension(x509.SubjectAlternativeName(san), critical=False)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key),
                              critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                   ca_cert.public_key()), critical=False))
    return builder.sign(ca_key, u.SIG_HASH)


# --- Servidor -------------------------------------------------------------
def issue_server_cert(cn: str, dns: list[str], ips: list[str], days: int = 365):
    ca_cert, ca_key = u.load_ca()
    key = u.new_key()
    san = [x509.DNSName(d) for d in dict.fromkeys([cn, *dns])]
    san += [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = _build(u.subject_name(cn), key.public_key(), ca_cert, ca_key,
                  ExtendedKeyUsageOID.SERVER_AUTH, san, days)
    u.save_key(key, u.STORE / "server.key")
    u.save_cert(cert, u.STORE / "server.crt")
    u.register_cert(cert, cn, "server")
    return cert


# --- Cliente (BYOD) -------------------------------------------------------
def make_csr(key, username: str) -> x509.CertificateSigningRequest:
    """CSR generado EN EL DISPOSITIVO: la clave privada nunca sale de el."""
    return (x509.CertificateSigningRequestBuilder()
            .subject_name(u.subject_name(username))
            .sign(key, u.SIG_HASH))

def _check_public_key(pub) -> None:
    ok_ec = isinstance(pub, ec.EllipticCurvePublicKey) and \
            pub.curve.name in ("secp256r1", "secp384r1")
    ok_rsa = isinstance(pub, rsa.RSAPublicKey) and pub.key_size >= 2048
    if not (ok_ec or ok_rsa):
        raise ValueError("Clave publica no aceptada (EC P-256/P-384 o RSA>=2048)")


def sign_client_csr(csr: x509.CertificateSigningRequest, username: str,
                    role: str, days: int = 365) -> x509.Certificate:
    """Firma un CSR tras validarlo. El subject lo fija la CA, NO el solicitante."""
    if role not in ROLES:
        raise ValueError(f"Rol invalido: {role}")
    if not csr.is_signature_valid:
        raise ValueError("CSR con firma invalida (no hay prueba de posesion de la clave)")
    _check_public_key(csr.public_key())
    
    if u.active_client_cert(username):
        # RF1 (inmutabilidad): hace falta revocar antes de re-emitir
        raise ValueError(f"'{username}' ya tiene un certificado activo; revocalo antes")

    ca_cert, ca_key = u.load_ca()
    san = [x509.RFC822Name(f"{username}@u-secure.es")]
    cert = _build(u.subject_name(username, ou=role), csr.public_key(), ca_cert, ca_key,
                  ExtendedKeyUsageOID.CLIENT_AUTH, san, days)
    u.register_cert(cert, username, "client", role)
    return cert


def issue_client_bundle(username: str, role: str, days: int = 365) -> tuple[Path, Path]:
    """Genera clave + CSR + certificado y los guarda en store/clients/ (para seed_users.py)."""
    key = u.new_key()
    cert = sign_client_csr(make_csr(key, username), username, role, days)
    key_path = u.CLIENTS / f"{username}.key"
    crt_path = u.CLIENTS / f"{username}.crt"
    u.save_key(key, key_path)
    u.save_cert(cert, crt_path)
    return key_path, crt_path


#Solo funciona si se ejecuta como script desde consola, no si se importa como modulo. Sirve para testear que funciona.
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("server")
    s.add_argument("--cn", default="vpn.u-secure.es")
    s.add_argument("--dns", nargs="*", default=["localhost"])
    s.add_argument("--ip", nargs="*", default=["127.0.0.1"])

    c = sub.add_parser("client")
    c.add_argument("--user", required=True)
    c.add_argument("--role", required=True, choices=sorted(ROLES))

    g = sub.add_parser("sign-csr")
    g.add_argument("--csr", required=True)
    g.add_argument("--user", required=True)
    g.add_argument("--role", required=True, choices=sorted(ROLES))

    a = ap.parse_args()
    if a.cmd == "server":
        cert = issue_server_cert(a.cn, a.dns, a.ip)
        print(f"[OK] Servidor: serial={cert.serial_number:x}")
    elif a.cmd == "client":
        k, c_ = issue_client_bundle(a.user, a.role)
        print(f"[OK] Cliente '{a.user}': {k} / {c_}")
    else:
        csr = x509.load_pem_x509_csr(Path(a.csr).read_bytes())
        cert = sign_client_csr(csr, a.user, a.role)
        out = Path(a.csr).with_suffix(".crt")
        out.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        print(f"[OK] Certificado firmado: {out}")