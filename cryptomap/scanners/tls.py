"""Live TLS endpoint scanner: performs a handshake, records the negotiated
protocol/cipher, and inventories the served certificate.

Verification is intentionally disabled — the goal is to inventory whatever
the endpoint actually serves, including expired or self-signed certs.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Iterator

from cryptography import x509

from ..model import AssetType, CryptoAsset, Exposure
from .keyinfo import classify_key

_TIMEOUT = 10.0


class TlsScanner:
    name = "tls"

    def __init__(self, host: str, port: int = 443,
                 exposure: Exposure = Exposure.PUBLIC):
        self.host = host
        self.port = port
        self.exposure = exposure

    def scan(self) -> Iterator[CryptoAsset]:
        location = f"{self.host}:{self.port}"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1  # inventory legacy too
        try:
            with socket.create_connection((self.host, self.port),
                                          timeout=_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as tls:
                    version = tls.version()
                    cipher = tls.cipher()  # (name, protocol, secret_bits)
                    der = tls.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError) as exc:
            yield CryptoAsset(
                name=f"unreachable endpoint {location}",
                asset_type=AssetType.TLS_ENDPOINT, algorithm="UNKNOWN",
                location=location, scanner=self.name, exposure=self.exposure,
                details={"error": str(exc)})
            return

        cipher_name = cipher[0] if cipher else "unknown"
        kex = _key_exchange_family(cipher_name, version)
        yield CryptoAsset(
            name=f"TLS endpoint {location}",
            asset_type=AssetType.TLS_ENDPOINT,
            algorithm=kex,
            location=location,
            scanner=self.name,
            exposure=self.exposure,
            details={
                "tls_version": version,
                "cipher_suite": cipher_name,
                "key_exchange_note": (
                    "TLS 1.3 hides the negotiated group from the ssl module; "
                    "ECDH (x25519/P-256) assumed" if version == "TLSv1.3"
                    else ""),
            },
        )

        if der:
            cert = x509.load_der_x509_certificate(der)
            family, bits, curve = classify_key(cert.public_key())
            not_after = cert.not_valid_after_utc
            yield CryptoAsset(
                name=cert.subject.rfc4514_string() or location,
                asset_type=AssetType.CERTIFICATE,
                algorithm=family, key_size=bits, curve=curve,
                location=location, scanner=self.name, exposure=self.exposure,
                details={
                    "issuer": cert.issuer.rfc4514_string(),
                    "not_after": not_after.isoformat(),
                    "expired": not_after < datetime.now(timezone.utc),
                    "signature_algorithm": cert.signature_algorithm_oid._name,
                },
            )


def _key_exchange_family(cipher_name: str, version: str | None) -> str:
    """Infer the key-exchange family from the cipher suite name. All of
    today's practically deployed key exchanges are quantum-vulnerable unless
    a PQC hybrid is in play (not visible through the ssl module)."""
    upper = cipher_name.upper()
    if version == "TLSv1.3":
        return "ECDH"  # x25519 or a NIST curve in virtually all deployments
    if "ECDHE" in upper or "ECDH" in upper:
        return "ECDH"
    if "DHE" in upper or upper.startswith("DH-"):
        return "DH"
    if upper.startswith(("AES", "CAMELLIA")) or "RSA" in upper:
        return "RSA"  # static-RSA key transport
    return "UNKNOWN"
