import socket
import ssl
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from qday.model import AssetType
from qday.scanners.certs import CertFileScanner
from qday.scanners.tls import TlsScanner, _group_family

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


def test_cert_scanner_prunes_skip_dirs(cert_dir):
    skipped = cert_dir / "node_modules"
    skipped.mkdir()
    (skipped / "copy.crt").write_bytes((cert_dir / "server.crt").read_bytes())
    assert len(list(CertFileScanner(cert_dir).scan())) == 2


def test_pkcs12_keystore(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = make_self_signed(key, "p12.test")
    blob = pkcs12.serialize_key_and_certificates(
        b"srv", key, cert, None, serialization.NoEncryption())
    (tmp_path / "store.p12").write_bytes(blob)

    assets = list(CertFileScanner(tmp_path).scan())
    by_type = {a.asset_type: a for a in assets}
    assert len(assets) == 2
    assert by_type[AssetType.KEY_MATERIAL].algorithm == "RSA"
    assert by_type[AssetType.KEY_MATERIAL].details["container"] == "pkcs12"
    assert by_type[AssetType.CERTIFICATE].key_size == 2048


def test_pkcs12_encrypted_keystore(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = make_self_signed(key, "p12.test")
    blob = pkcs12.serialize_key_and_certificates(
        b"srv", key, cert, None,
        serialization.BestAvailableEncryption(b"hunter2"))
    (tmp_path / "locked.pfx").write_bytes(blob)

    (asset,) = CertFileScanner(tmp_path).scan()
    assert asset.algorithm == "UNKNOWN"
    assert asset.details["encrypted"] is True
    assert asset.details["container"] == "pkcs12"


def test_ssh_key_files(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ed25519

    rsa_pub = rsa.generate_private_key(
        public_exponent=65537, key_size=2048).public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH).decode()
    ed_pub = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH).decode()

    (tmp_path / "authorized_keys").write_text(
        "# admins\n"
        f'command="/bin/true",no-pty {rsa_pub} ops@example\n'
        f"{ed_pub} dev@example\n"
        "not a key line\n")
    (tmp_path / "known_hosts").write_text(
        f"github.com,140.82.121.3 {ed_pub}\n")

    assets = sorted(CertFileScanner(tmp_path).scan(),
                    key=lambda a: a.location)
    assert [a.algorithm for a in assets] == ["RSA", "EdDSA", "EdDSA"]
    assert assets[0].location == "authorized_keys:2"
    assert assets[0].key_size == 2048
    assert assets[2].details["source"] == "known_hosts"


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
    assert endpoint.algorithm in {"ECDH", "DH", "RSA", "X25519", "PQC-HYBRID"}
    served = by_type[AssetType.CERTIFICATE]
    assert served.algorithm == "RSA" and served.key_size == 2048
    assert "localhost" in served.name
    assert served.details["chain_role"] == "leaf"


def test_tls_scanner_unreachable():
    (asset,) = TlsScanner("127.0.0.1", 1).scan()
    assert asset.algorithm == "UNKNOWN"
    assert "error" in asset.details


def test_group_family_classification():
    assert _group_family("X25519MLKEM768") == "PQC-HYBRID"
    assert _group_family("SecP256r1MLKEM768") == "PQC-HYBRID"
    assert _group_family("X25519Kyber768Draft00") == "PQC-HYBRID"
    assert _group_family("x25519") == "X25519"
    assert _group_family("x448") == "X448"
    assert _group_family("secp384r1") == "ECDH"
    assert _group_family("ffdhe2048") == "DH"
