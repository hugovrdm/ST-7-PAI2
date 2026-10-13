import argparse
import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from pki import pki_utils as u


def create_ca(years: int = 10) -> None:
    key = u.new_key()
    name = u.subject_name(u.CA_CN)

    cert = (x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)  # autofirmado
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(u.now() - dt.timedelta(minutes=1))
            .not_valid_after(u.now() + dt.timedelta(days=365 * years))
            # CA:TRUE, path_length=0 -> solo firma certificados finales
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, u.SIG_HASH))

    u.save_key(key, u.CA_KEY, u.ca_password())
    u.save_cert(cert, u.CA_CERT)
    u.save_index({"certs": []})
    u.build_crl()

    print(f"[OK] CA creada: {u.CA_CERT}")
    print(f"     Subject : {cert.subject.rfc4514_string()}")
    print(f"     SHA-256 : {u.fingerprint(cert)}")
    print(f"     Clave CA protegida con password: {'SI' if u.ca_password() else 'NO'}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--years", type=int, default=10)
    args = ap.parse_args()
    if u.CA_CERT.exists() and not args.force:
        raise SystemExit("La CA ya existe. Usa --force para regenerarla.")
    create_ca(args.years)