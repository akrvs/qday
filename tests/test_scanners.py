import socket
import ssl
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from qday.model import AssetType
from qday.scanners.certs import CertFileScanner
from qday.scanners.tls import TlsScanner

from .conftest import make_self_signed


def test_cert_file_scanner(cert_dir):
    assets = list(CertFileScanner(cert_dir).scan())
    by_type = {a.asset_type: a for a in assets}
    assert len(assets) == 2  # decoy pem must not produce an asset

    cert = by_type[AssetType.CERTIFICATE]
    assert cert.algorithm == "RSA" and cert.key_size == 2048
    assert cert.quantum_vulnerable
    assert cert.details["expired"] is False

    key = by_type[AssetType.KEY_MATERIAL]
    assert key.algorithm == "EC" and key.curve == "secp256r1"
    assert key.details["private"] is True


def test_tls_scanner_against_local_server(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = make_self_signed(key, "localhost")
    cert_file = tmp_path / "c.pem"
    key_file = tmp_path / "k.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve_once():
        conn, _ = listener.accept()
        try:
            with ctx.wrap_socket(conn, server_side=True):
                pass
        except ssl.SSLError:
            pass  # client closes right after handshake

    t = threading.Thread(target=serve_once, daemon=True)
    t.start()

    assets = list(TlsScanner("127.0.0.1", port).scan())
    t.join(timeout=5)
    listener.close()

    by_type = {a.asset_type: a for a in assets}
    endpoint = by_type[AssetType.TLS_ENDPOINT]
    assert endpoint.details["tls_version"].startswith("TLS")
    assert endpoint.algorithm in {"ECDH", "DH", "RSA"}
    served = by_type[AssetType.CERTIFICATE]
    assert served.algorithm == "RSA" and served.key_size == 2048
    assert "localhost" in served.name
    assert served.details["chain_role"] == "leaf"


def test_tls_scanner_unreachable():
    (asset,) = TlsScanner("127.0.0.1", 1).scan()
    assert asset.algorithm == "UNKNOWN"
    assert "error" in asset.details
