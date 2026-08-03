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
                 exposure: Exposure = Exposure.PUBLIC,
                 starttls: str | None = None):
        self.host = host
        self.port = port
        self.exposure = exposure
        self.starttls = starttls  # "smtp" | "imap" | "pop3" | None

    def scan(self) -> Iterator[CryptoAsset]:
        location = f"{self.host}:{self.port}"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1  # inventory legacy too
        try:
            with socket.create_connection((self.host, self.port),
                                          timeout=_TIMEOUT) as sock:
                if self.starttls:
                    _starttls_dialog(sock, self.starttls)
                with ctx.wrap_socket(sock, server_hostname=self.host) as tls:
                    version = tls.version()
                    cipher = tls.cipher()  # (name, protocol, secret_bits)
                    group = _negotiated_group(tls)
                    der = tls.getpeercert(binary_form=True)
                    chain_der = _peer_chain(tls)
        except (OSError, ssl.SSLError) as exc:
            yield CryptoAsset(
                name=f"unreachable endpoint {location}",
                asset_type=AssetType.TLS_ENDPOINT, algorithm="UNKNOWN",
                location=location, scanner=self.name, exposure=self.exposure,
                details={"error": str(exc)})
            return

        cipher_name = cipher[0] if cipher else "unknown"
        details = {"tls_version": version, "cipher_suite": cipher_name}
        if self.starttls:
            details["starttls"] = self.starttls
        if group:
            kex = _group_family(group)
            details["key_exchange_group"] = group
        else:
            kex = _key_exchange_family(cipher_name, version)
            if version == "TLSv1.3":
                details["key_exchange_note"] = (
                    "negotiated group not exposed by this Python runtime; "
                    "ECDH (x25519/P-256) assumed")
        yield CryptoAsset(
            name=f"TLS endpoint {location}",
            asset_type=AssetType.TLS_ENDPOINT,
            algorithm=kex,
            location=location,
            scanner=self.name,
            exposure=self.exposure,
            details=details,
        )

        # Whole served chain: a PQC-migrated leaf under an RSA intermediate
        # is still a quantum-vulnerable trust path, so intermediates count.
        chain = chain_der if chain_der else ([der] if der else [])
        for position, cert_der in enumerate(chain):
            cert = x509.load_der_x509_certificate(cert_der)
            family, bits, curve = classify_key(cert.public_key())
            not_after = cert.not_valid_after_utc
            role = "leaf" if position == 0 else (
                "root" if position == len(chain) - 1 and len(chain) > 1
                else "intermediate")
            yield CryptoAsset(
                name=cert.subject.rfc4514_string() or location,
                asset_type=AssetType.CERTIFICATE,
                algorithm=family, key_size=bits, curve=curve,
                location=location, scanner=self.name, exposure=self.exposure,
                details={
                    "chain_role": role,
                    "issuer": cert.issuer.rfc4514_string(),
                    "not_after": not_after.isoformat(),
                    "expired": not_after < datetime.now(timezone.utc),
                    "signature_algorithm": cert.signature_algorithm_oid._name,
                },
            )


def _starttls_dialog(sock: socket.socket, proto: str) -> None:
    """Plaintext pre-dialog that upgrades an SMTP/IMAP/POP3 connection to
    TLS. Raises OSError on refusal so the caller records an unreachable
    endpoint. Reads stop exactly at the upgrade reply, so no TLS bytes are
    swallowed by the line buffer (same approach as smtplib/imaplib)."""
    reader = sock.makefile("rb")

    def smtp_reply() -> bytes:
        while True:
            line = reader.readline()
            if not line or line[3:4] != b"-":  # "250-" continues, "250 " ends
                return line

    if proto == "smtp":
        smtp_reply()
        sock.sendall(b"EHLO qday.invalid\r\n")
        smtp_reply()
        sock.sendall(b"STARTTLS\r\n")
        reply = smtp_reply()
        if not reply.startswith(b"220"):
            raise OSError(f"STARTTLS refused: {reply[:80]!r}")
    elif proto == "imap":
        reader.readline()
        sock.sendall(b"q1 STARTTLS\r\n")
        while True:
            line = reader.readline()
            if not line or line.startswith(b"q1 "):
                if not line.startswith(b"q1 OK"):
                    raise OSError(f"STARTTLS refused: {line[:80]!r}")
                return
    elif proto == "pop3":
        reader.readline()
        sock.sendall(b"STLS\r\n")
        reply = reader.readline()
        if not reply.startswith(b"+OK"):
            raise OSError(f"STLS refused: {reply[:80]!r}")
    else:
        raise OSError(f"unsupported STARTTLS protocol {proto!r}")


def _peer_chain(tls: ssl.SSLSocket) -> list[bytes]:
    """Full served chain as DER blobs, leaf first (Python 3.13+; empty list
    on older runtimes, where the caller falls back to the leaf only)."""
    getter = getattr(tls, "get_unverified_chain", None)
    if getter is None:
        return []
    try:
        chain = getter() or []
    except ssl.SSLError:
        return []
    return [c if isinstance(c, bytes)
            else ssl.PEM_cert_to_DER_cert(c.public_bytes())
            for c in chain]


def _negotiated_group(tls: ssl.SSLSocket) -> str | None:
    getter = getattr(tls, "group", None)
    if getter is None:
        return None
    try:
        return getter()
    except ssl.SSLError:
        return None


def _group_family(group: str) -> str:
    g = group.lower()
    if "mlkem" in g or "kyber" in g or "sntrup" in g or "frodo" in g:
        return "PQC-HYBRID"
    if "x25519" in g:
        return "X25519"
    if "x448" in g:
        return "X448"
    if g.startswith("ffdhe"):
        return "DH"
    return "ECDH"


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
