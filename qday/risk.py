"""Risk scoring: algorithm vulnerability × data lifespan × exposure.

Scores land on a 0–10 scale. The lifespan multiplier encodes the
"harvest now, decrypt later" threat: long-lived data protected by
quantum-vulnerable crypto is already at risk today, because ciphertext
recorded now can be decrypted once a CRQC exists.
"""

from __future__ import annotations

from .model import CryptoAsset, Exposure

# Base severity by algorithm family (before lifespan/exposure multipliers).
_BROKEN_TODAY = 10.0      # weak even classically (e.g. RSA < 2048)
_SHOR_BROKEN = 8.0        # sound today, broken by a quantum computer
_GROVER_WEAK = 3.0        # 128-bit symmetric: margin halved, not broken
_UNKNOWN = 5.0            # can't classify — deserves a human look
_SAFE = 0.0

_LIFESPAN_MULT = ((15, 1.25), (7, 1.0), (3, 0.8), (0, 0.6))
_EXPOSURE_MULT = {Exposure.PUBLIC: 1.25, Exposure.INTERNAL: 1.0,
                  Exposure.LOCAL: 0.85}

LEVELS = ((8.0, "critical"), (6.0, "high"), (3.0, "medium"),
          (0.001, "low"), (0.0, "none"))

_REMEDIATION = {
    "RSA": "ML-DSA-65 (sign) / ML-KEM-768 (encrypt)",
    "EC": "ML-DSA-65 / ML-KEM-768",
    "ECDSA": "ML-DSA-65",
    "EdDSA": "ML-DSA-65",
    "DSA": "ML-DSA-65",
    "ECDH": "ML-KEM-768",
    "DH": "ML-KEM-768",
    "X25519": "ML-KEM-768",
    "X448": "ML-KEM-1024",
    "DES": "AES-256",
    "3DES": "AES-256",
}


def remediation(algorithm: str, asset_type: str = "",
                key_size: int | None = None) -> str | None:
    from .model import is_quantum_vulnerable
    if asset_type == "tls-endpoint" and is_quantum_vulnerable(algorithm):
        return "TLS 1.3 hybrid kex (X25519MLKEM768)"
    if asset_type == "ssh-endpoint" and is_quantum_vulnerable(algorithm):
        return "hybrid kex (mlkem768x25519 / sntrup761x25519)"
    if algorithm == "AES" and (key_size or 0) <= 128:
        return "AES-256"
    return _REMEDIATION.get(algorithm)


def _base_severity(asset: CryptoAsset) -> float:
    if asset.pqc_ready:
        return _SAFE
    if asset.quantum_vulnerable:
        if _classically_weak(asset):
            return _BROKEN_TODAY
        return _SHOR_BROKEN
    family = asset.algorithm
    if family in {"DES", "3DES"}:
        return _BROKEN_TODAY
    if family == "AES" and (asset.key_size or 0) <= 128:
        return _GROVER_WEAK
    if family in {"AES", "CHACHA20", "SHA-2", "SHA-3"}:
        return _SAFE
    return _UNKNOWN


def _classically_weak(asset: CryptoAsset) -> bool:
    bits = asset.key_size
    if bits is None:
        return False
    if asset.algorithm in {"RSA", "DH", "DSA"}:
        return bits < 2048
    if asset.algorithm in {"EC", "ECDSA", "ECDH"}:
        return bits < 224
    return False


def _lifespan_multiplier(years: int) -> float:
    for threshold, mult in _LIFESPAN_MULT:
        if years >= threshold:
            return mult
    return _LIFESPAN_MULT[-1][1]


def score_asset(asset: CryptoAsset) -> tuple[float, str]:
    """Return (score 0–10, level). Expired certs get a small bump: they
    signal unmanaged crypto, the population least likely to migrate."""
    score = (_base_severity(asset)
             * _lifespan_multiplier(asset.data_lifespan_years)
             * _EXPOSURE_MULT[asset.exposure])
    if asset.details.get("expired"):
        score += 0.5
    score = round(min(score, 10.0), 2)
    for threshold, level in LEVELS:
        if score >= threshold:
            return score, level
    return score, "none"
