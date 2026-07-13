import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def make_self_signed(key, cn: str) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )


@pytest.fixture
def cert_dir(tmp_path):
    """Directory with an RSA cert, an EC private key, and a decoy file."""
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = make_self_signed(rsa_key, "unit.test")
    (tmp_path / "server.crt").write_bytes(
        cert.public_bytes(serialization.Encoding.PEM))

    ec_key = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "signer.key").write_bytes(ec_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))

    (tmp_path / "notes.pem").write_bytes(b"not actually pem")
    return tmp_path
