"""Core data model: the CryptoAsset and algorithm classification.

Every scanner normalizes its findings into CryptoAsset instances; everything
downstream (store, risk, CBOM, dashboard) consumes only this type.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum


class AssetType(str, Enum):
    CERTIFICATE = "certificate"
    TLS_ENDPOINT = "tls-endpoint"
    KEY_MATERIAL = "key-material"
    CODE_FINDING = "code-finding"
    DEPENDENCY = "dependency"


class Exposure(str, Enum):
    PUBLIC = "public"      # reachable from the internet
    INTERNAL = "internal"  # reachable inside the org network
    LOCAL = "local"        # at rest / in a repo, not directly reachable


# Families broken by Shor's algorithm on a cryptographically relevant
# quantum computer. Ed25519/Ed448/X25519 are elliptic-curve schemes and
# therefore vulnerable despite their modern reputation.
QUANTUM_VULNERABLE_FAMILIES = {
    "RSA", "EC", "ECDSA", "ECDH", "DH", "DSA", "EdDSA", "X25519", "X448",
}

# NIST-standardized (or draft) post-quantum families.
PQC_FAMILIES = {"ML-KEM", "ML-DSA", "SLH-DSA", "FN-DSA", "LMS", "XMSS", "HSS",
                "PQC-HYBRID"}

# Symmetric/hash primitives: only Grover-affected, acceptable at large sizes.
SYMMETRIC_FAMILIES = {"AES", "CHACHA20", "3DES", "DES", "SHA-2", "SHA-3"}

# Map raw names as reported by libraries/certs to a canonical family.
_ALIAS_TO_FAMILY = {
    "rsa": "RSA",
    "rsassa-pss": "RSA",
    "rsaes-oaep": "RSA",
    "ec": "EC",
    "ecdsa": "ECDSA",
    "ecdh": "ECDH",
    "ecdhe": "ECDH",
    "secp256r1": "EC",
    "secp384r1": "EC",
    "secp521r1": "EC",
    "prime256v1": "EC",
    "dh": "DH",
    "dhe": "DH",
    "dsa": "DSA",
    "ed25519": "EdDSA",
    "ed448": "EdDSA",
    "x25519": "X25519",
    "x448": "X448",
    "ml-kem": "ML-KEM",
    "kyber": "ML-KEM",
    "ml-dsa": "ML-DSA",
    "dilithium": "ML-DSA",
    "slh-dsa": "SLH-DSA",
    "sphincs+": "SLH-DSA",
    "falcon": "FN-DSA",
    "fn-dsa": "FN-DSA",
    "aes": "AES",
    "chacha20": "CHACHA20",
    "3des": "3DES",
    "des": "DES",
}

# Make canonicalization idempotent: every family name maps to itself.
_ALIAS_TO_FAMILY.update({
    f.lower(): f
    for f in (QUANTUM_VULNERABLE_FAMILIES | PQC_FAMILIES | SYMMETRIC_FAMILIES)
})


def canonical_family(name: str) -> str:
    """Normalize an algorithm name to its canonical family (upper-cased
    passthrough when unknown, so nothing silently disappears)."""
    return _ALIAS_TO_FAMILY.get(name.strip().lower(), name.strip().upper())


def known_family(name: str) -> str | None:
    """Canonical family if the name or a dash-prefix of it is a known alias
    ("ml-dsa-65" -> "ML-DSA"); None when nothing matches."""
    parts = name.strip().lower().split("-")
    for end in range(len(parts), 0, -1):
        family = _ALIAS_TO_FAMILY.get("-".join(parts[:end]))
        if family:
            return family
    return None


def is_quantum_vulnerable(family: str) -> bool:
    return canonical_family(family) in QUANTUM_VULNERABLE_FAMILIES


def is_pqc(family: str) -> bool:
    return canonical_family(family) in PQC_FAMILIES


@dataclass
class CryptoAsset:
    name: str
    asset_type: AssetType
    algorithm: str                    # canonical family, e.g. "RSA"
    location: str                     # URL, host:port, file path, file:line
    scanner: str                      # which scanner produced it
    key_size: int | None = None       # bits (modulus / curve field size)
    curve: str | None = None
    exposure: Exposure = Exposure.LOCAL
    data_lifespan_years: int = 10     # human-supplied; conservative default
    details: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.algorithm = canonical_family(self.algorithm)

    @property
    def quantum_vulnerable(self) -> bool:
        return is_quantum_vulnerable(self.algorithm)

    @property
    def pqc_ready(self) -> bool:
        return is_pqc(self.algorithm)

    @property
    def asset_id(self) -> str:
        """Stable identity across scan runs, so history/trends can track an
        asset even as scores or metadata change."""
        raw = "|".join([self.asset_type.value, self.algorithm,
                        self.location, self.name])
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_row(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "asset_type": self.asset_type.value,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "curve": self.curve,
            "location": self.location,
            "scanner": self.scanner,
            "exposure": self.exposure.value,
            "data_lifespan_years": self.data_lifespan_years,
            "quantum_vulnerable": int(self.quantum_vulnerable),
            "details_json": json.dumps(self.details, default=str),
        }
