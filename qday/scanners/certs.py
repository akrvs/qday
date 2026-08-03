"""Certificate/key file scanner: walks a directory tree and inventories
X.509 certificates and raw key material found on disk or in repos."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from ..model import AssetType, CryptoAsset, Exposure
from .base import walk_files
from .keyinfo import classify_key

CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".key", ".pub", ".p8"}
P12_EXTENSIONS = {".p12", ".pfx"}
SSH_FILE_NAMES = {"authorized_keys", "known_hosts"}
_SSH_KEY_TYPE = re.compile(r"^(sk-)?(ssh|ecdsa)-[\w.@-]+$")
_SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__"}
_MAX_FILE_BYTES = 1_000_000


class CertFileScanner:
    name = "certs"

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def scan(self) -> Iterator[CryptoAsset]:
        for path in walk_files(self.root, _SKIP_DIRS, _MAX_FILE_BYTES):
            suffix = path.suffix.lower()
            if suffix in P12_EXTENSIONS:
                yield from self._scan_pkcs12(path)
            elif suffix in CERT_EXTENSIONS:
                yield from self._scan_file(path)
            elif path.name in SSH_FILE_NAMES:
                yield from self._scan_ssh_lines(path)

    def _scan_file(self, path: Path) -> Iterator[CryptoAsset]:
        try:
            data = path.read_bytes()
        except OSError:
            return
        rel = str(path.relative_to(self.root))
        found = False
        for cert in _load_certs(data):
            found = True
            yield self._cert_asset(cert, rel)
        if not found:
            asset = _key_asset(data, rel)
            if asset:
                yield asset

    def _scan_pkcs12(self, path: Path) -> Iterator[CryptoAsset]:
        try:
            data = path.read_bytes()
        except OSError:
            return
        rel = str(path.relative_to(self.root))
        try:
            key, cert, extras = pkcs12.load_key_and_certificates(data, None)
        except (ValueError, UnsupportedAlgorithm):
            # Password-protected (or unreadable) keystore: the algorithm is
            # hidden, but a keystore on disk is still inventory-worthy.
            yield CryptoAsset(
                name=f"encrypted keystore ({rel})",
                asset_type=AssetType.KEY_MATERIAL, algorithm="UNKNOWN",
                location=rel, scanner=self.name,
                details={"encrypted": True, "container": "pkcs12"})
            return
        if key is not None:
            family, bits, curve = classify_key(key)
            yield CryptoAsset(
                name=f"private key ({rel})",
                asset_type=AssetType.KEY_MATERIAL,
                algorithm=family, key_size=bits, curve=curve,
                location=rel, scanner=self.name,
                details={"private": True, "container": "pkcs12"})
        for c in ([cert] if cert else []) + list(extras or []):
            yield self._cert_asset(c, rel)

    def _scan_ssh_lines(self, path: Path) -> Iterator[CryptoAsset]:
        """authorized_keys / known_hosts: one public key per line, with
        leading options (authorized_keys) or host patterns (known_hosts)
        before the key-type token."""
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return
        rel = str(path.relative_to(self.root))
        for lineno, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key = _ssh_line_key(line)
            if key is None:
                continue
            family, bits, curve = classify_key(key)
            yield CryptoAsset(
                name=f"{path.name} entry ({rel}:{lineno})",
                asset_type=AssetType.KEY_MATERIAL,
                algorithm=family, key_size=bits, curve=curve,
                location=f"{rel}:{lineno}", scanner=self.name,
                details={"private": False, "source": path.name})

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


def _ssh_line_key(line: str):
    """Public key from an authorized_keys/known_hosts line, or None. Finds
    the key-type token so leading options/host fields don't matter."""
    tokens = line.split()
    for i, tok in enumerate(tokens[:-1]):
        if _SSH_KEY_TYPE.match(tok):
            try:
                return serialization.load_ssh_public_key(
                    f"{tok} {tokens[i + 1]}".encode())
            except (ValueError, UnsupportedAlgorithm):
                return None
    return None


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
