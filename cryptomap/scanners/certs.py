"""Certificate/key file scanner: walks a directory tree and inventories
X.509 certificates and raw key material found on disk or in repos."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

from ..model import AssetType, CryptoAsset, Exposure
from .keyinfo import classify_key

CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".key", ".pub", ".p8"}
_SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__"}
_MAX_FILE_BYTES = 1_000_000


class CertFileScanner:
    name = "certs"

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def scan(self) -> Iterator[CryptoAsset]:
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in CERT_EXTENSIONS:
                continue
            if _SKIP_DIRS.intersection(path.parts):
                continue
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            yield from self._scan_file(path)

    def _scan_file(self, path: Path) -> Iterator[CryptoAsset]:
        data = path.read_bytes()
        rel = str(path.relative_to(self.root))
        found = False
        for cert in _load_certs(data):
            found = True
            yield self._cert_asset(cert, rel)
        if not found:
            asset = _key_asset(data, rel)
            if asset:
                yield asset

    def _cert_asset(self, cert: x509.Certificate, rel: str) -> CryptoAsset:
        family, bits, curve = classify_key(cert.public_key())
        not_after = cert.not_valid_after_utc
        return CryptoAsset(
            name=cert.subject.rfc4514_string() or rel,
            asset_type=AssetType.CERTIFICATE,
            algorithm=family,
            key_size=bits,
            curve=curve,
            location=rel,
            scanner=self.name,
            exposure=Exposure.LOCAL,
            details={
                "issuer": cert.issuer.rfc4514_string(),
                "not_after": not_after.isoformat(),
                "expired": not_after < datetime.now(timezone.utc),
                "signature_algorithm": cert.signature_algorithm_oid._name,
                "serial": format(cert.serial_number, "x"),
            },
        )


def _load_certs(data: bytes) -> list[x509.Certificate]:
    """Load every certificate in a blob (PEM bundle or single DER)."""
    if b"-----BEGIN CERTIFICATE-----" in data:
        try:
            return x509.load_pem_x509_certificates(data)
        except ValueError:
            return []
    try:
        return [x509.load_der_x509_certificate(data)]
    except ValueError:
        return []


def _key_asset(data: bytes, rel: str) -> CryptoAsset | None:
    """Classify a standalone key file (PEM/DER/OpenSSH, public or private)."""
    is_private = False
    key = None
    for loader, private in (
        (serialization.load_pem_public_key, False),
        (serialization.load_ssh_public_key, False),
        (lambda d: serialization.load_pem_private_key(d, password=None), True),
        (serialization.load_der_public_key, False),
        (lambda d: serialization.load_der_private_key(d, password=None), True),
    ):
        try:
            key = loader(data)
            is_private = private
            break
        except (ValueError, TypeError, UnsupportedAlgorithm):
            continue
    if key is None:
        if b"ENCRYPTED" in data and b"PRIVATE KEY" in data:
            # Can't read the algorithm, but an encrypted private key on disk
            # is still inventory-worthy.
            return CryptoAsset(
                name="encrypted private key", asset_type=AssetType.KEY_MATERIAL,
                algorithm="UNKNOWN", location=rel, scanner="certs",
                details={"encrypted": True, "private": True})
        return None
    family, bits, curve = classify_key(key)
    return CryptoAsset(
        name=("private" if is_private else "public") + f" key ({rel})",
        asset_type=AssetType.KEY_MATERIAL,
        algorithm=family, key_size=bits, curve=curve,
        location=rel, scanner="certs",
        details={"private": is_private},
    )
