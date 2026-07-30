from __future__ import annotations

import socket
from typing import Iterator

from ..model import AssetType, CryptoAsset, Exposure

_TIMEOUT = 10.0
_MSG_KEXINIT = 20
_MAX_PACKET = 65536

_HOSTKEY_FAMILIES = (
    ("ssh-ed25519", "EdDSA", None),
    ("ssh-ed448", "EdDSA", None),
    ("rsa-sha2", "RSA", None),
    ("ssh-rsa", "RSA", None),
    ("ecdsa-sha2-nistp256", "ECDSA", 256),
    ("ecdsa-sha2-nistp384", "ECDSA", 384),
    ("ecdsa-sha2-nistp521", "ECDSA", 521),
    ("ssh-dss", "DSA", None),
)


class SshProtocolError(Exception):
    pass


class SshScanner:
    name = "ssh"

    def __init__(self, host: str, port: int = 22,
                 exposure: Exposure = Exposure.PUBLIC):
        self.host = host
        self.port = port
        self.exposure = exposure

    def scan(self) -> Iterator[CryptoAsset]:
        location = f"{self.host}:{self.port}"
        try:
            banner, kex_algos, host_key_algos = _probe(self.host, self.port)
        except (OSError, SshProtocolError) as exc:
            yield CryptoAsset(
                name=f"unreachable SSH endpoint {location}",
                asset_type=AssetType.SSH_ENDPOINT, algorithm="UNKNOWN",
                location=location, scanner=self.name, exposure=self.exposure,
                details={"error": str(exc)})
            return

        yield CryptoAsset(
            name=f"SSH endpoint {location}",
            asset_type=AssetType.SSH_ENDPOINT,
            algorithm=_kex_family(kex_algos),
            location=location,
            scanner=self.name,
            exposure=self.exposure,
            details={
                "banner": banner,
                "kex_algorithms": kex_algos,
                "host_key_algorithms": host_key_algos,
            },
        )
        for (family, bits), algos in _host_key_families(host_key_algos):
            yield CryptoAsset(
                name=f"SSH host key {family}"
                     + (f"-{bits}" if bits else ""),
                asset_type=AssetType.KEY_MATERIAL,
                algorithm=family,
                key_size=bits,
                location=location,
                scanner=self.name,
                exposure=self.exposure,
                details={"host_key_algorithms": algos, "banner": banner},
            )


def _probe(host: str, port: int) -> tuple[str, list[str], list[str]]:
    with socket.create_connection((host, port), timeout=_TIMEOUT) as sock:
        sock.settimeout(_TIMEOUT)
        with sock.makefile("rb") as fh:
            banner = None
            for _ in range(20):
                line = fh.readline(1024)
                if not line:
                    raise SshProtocolError("connection closed before banner")
                if line.startswith(b"SSH-"):
                    banner = line.strip().decode("ascii", "replace")
                    break
            if banner is None:
                raise SshProtocolError("no SSH banner received")
            sock.sendall(b"SSH-2.0-qday_scanner\r\n")
            payload = _read_packet(fh)
            if not payload or payload[0] != _MSG_KEXINIT:
                raise SshProtocolError("expected KEXINIT")
    kex_algos, host_key_algos = _parse_kexinit(payload)
    return banner, kex_algos, host_key_algos


def _read_packet(fh) -> bytes:
    header = fh.read(5)
    if len(header) < 5:
        raise SshProtocolError("truncated packet header")
    packet_len = int.from_bytes(header[:4], "big")
    padding_len = header[4]
    if not padding_len + 1 <= packet_len <= _MAX_PACKET:
        raise SshProtocolError(f"bad packet length {packet_len}")
    body = fh.read(packet_len - 1)
    if len(body) < packet_len - 1:
        raise SshProtocolError("truncated packet body")
    return body[:packet_len - 1 - padding_len]


def _parse_kexinit(payload: bytes) -> tuple[list[str], list[str]]:
    offset = 17
    lists = []
    for _ in range(2):
        if offset + 4 > len(payload):
            raise SshProtocolError("truncated KEXINIT")
        length = int.from_bytes(payload[offset:offset + 4], "big")
        offset += 4
        if offset + length > len(payload):
            raise SshProtocolError("truncated KEXINIT")
        names = payload[offset:offset + length].decode("ascii", "replace")
        lists.append([n for n in names.split(",") if n])
        offset += length
    return lists[0], lists[1]


def _kex_family(kex_algos: list[str]) -> str:
    joined = ",".join(kex_algos).lower()
    if "sntrup" in joined or "mlkem" in joined or "kyber" in joined:
        return "PQC-HYBRID"
    for algo in kex_algos:
        a = algo.lower()
        if a.startswith("curve25519"):
            return "X25519"
        if a.startswith("curve448"):
            return "X448"
        if a.startswith("ecdh-sha2"):
            return "ECDH"
        if a.startswith("diffie-hellman"):
            return "DH"
    return "UNKNOWN"


def _host_key_families(
        algos: list[str]) -> list[tuple[tuple[str, int | None], list[str]]]:
    found: dict[tuple[str, int | None], list[str]] = {}
    for algo in algos:
        a = algo.lower()
        for suffix in ("-cert-v01@openssh.com", "@openssh.com"):
            a = a.removesuffix(suffix)
        for prefix, family, bits in _HOSTKEY_FAMILIES:
            if a.startswith(prefix):
                found.setdefault((family, bits), []).append(algo)
                break
    return sorted(found.items())
