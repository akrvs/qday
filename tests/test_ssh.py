import socket
import threading

from qday.model import AssetType
from qday.scanners.ssh import (SshScanner, _host_key_families, _kex_family,
                               _parse_kexinit)


def _name_list(names):
    data = ",".join(names).encode()
    return len(data).to_bytes(4, "big") + data


def _kexinit_payload(kex, host_keys):
    payload = bytes([20]) + b"\x00" * 16
    payload += _name_list(kex) + _name_list(host_keys)
    for _ in range(8):
        payload += _name_list([])
    payload += b"\x00" + b"\x00\x00\x00\x00"
    return payload


def _packet(payload):
    padding = 8
    length = len(payload) + padding + 1
    return (length.to_bytes(4, "big") + bytes([padding])
            + payload + b"\x00" * padding)


def _fake_ssh_server(kex, host_keys):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve_once():
        conn, _ = listener.accept()
        conn.sendall(b"SSH-2.0-OpenSSH_9.9\r\n")
        conn.recv(1024)
        conn.sendall(_packet(_kexinit_payload(kex, host_keys)))
        conn.close()

    thread = threading.Thread(target=serve_once, daemon=True)
    thread.start()
    return listener, thread, port


def test_ssh_scanner_hybrid_kex():
    listener, thread, port = _fake_ssh_server(
        ["sntrup761x25519-sha512@openssh.com", "curve25519-sha256"],
        ["rsa-sha2-512", "ssh-ed25519", "ecdsa-sha2-nistp256"])
    assets = list(SshScanner("127.0.0.1", port).scan())
    thread.join(timeout=5)
    listener.close()

    endpoint = next(a for a in assets
                    if a.asset_type == AssetType.SSH_ENDPOINT)
    assert endpoint.algorithm == "PQC-HYBRID"
    assert endpoint.pqc_ready
    assert endpoint.details["banner"] == "SSH-2.0-OpenSSH_9.9"
    assert "curve25519-sha256" in endpoint.details["kex_algorithms"]

    keys = {a.algorithm: a for a in assets
            if a.asset_type == AssetType.KEY_MATERIAL}
    assert set(keys) == {"RSA", "EdDSA", "ECDSA"}
    assert keys["ECDSA"].key_size == 256
    assert keys["RSA"].quantum_vulnerable


def test_ssh_scanner_classical_kex():
    listener, thread, port = _fake_ssh_server(
        ["curve25519-sha256", "diffie-hellman-group14-sha256"],
        ["ssh-ed25519"])
    assets = list(SshScanner("127.0.0.1", port).scan())
    thread.join(timeout=5)
    listener.close()

    endpoint = next(a for a in assets
                    if a.asset_type == AssetType.SSH_ENDPOINT)
    assert endpoint.algorithm == "X25519"
    assert endpoint.quantum_vulnerable


def test_ssh_scanner_unreachable():
    (asset,) = SshScanner("127.0.0.1", 1).scan()
    assert asset.algorithm == "UNKNOWN"
    assert "error" in asset.details


def test_kex_family():
    assert _kex_family(["mlkem768x25519-sha256"]) == "PQC-HYBRID"
    assert _kex_family(["sntrup761x25519-sha512@openssh.com"]) == "PQC-HYBRID"
    assert _kex_family(["curve25519-sha256@libssh.org"]) == "X25519"
    assert _kex_family(["ecdh-sha2-nistp256"]) == "ECDH"
    assert _kex_family(["diffie-hellman-group14-sha1"]) == "DH"
    assert _kex_family(["ext-info-s"]) == "UNKNOWN"


def test_host_key_families_strips_cert_suffix():
    families = dict(_host_key_families(
        ["rsa-sha2-512-cert-v01@openssh.com", "ssh-rsa",
         "ecdsa-sha2-nistp384", "ssh-dss"]))
    assert ("RSA", None) in families
    assert len(families[("RSA", None)]) == 2
    assert ("ECDSA", 384) in families
    assert ("DSA", None) in families


def test_parse_kexinit_roundtrip():
    kex, host_keys = _parse_kexinit(
        _kexinit_payload(["curve25519-sha256"], ["ssh-ed25519"]))
    assert kex == ["curve25519-sha256"]
    assert host_keys == ["ssh-ed25519"]
