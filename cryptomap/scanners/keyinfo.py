"""Shared helper: classify a `cryptography` public/private key object into
(algorithm family, key size in bits, curve name)."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import (
    dh, dsa, ec, ed448, ed25519, rsa, x448, x25519,
)


def classify_key(key) -> tuple[str, int | None, str | None]:
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return "RSA", key.key_size, None
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return "EC", key.curve.key_size, key.curve.name
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return "DSA", key.key_size, None
    if isinstance(key, (dh.DHPublicKey, dh.DHPrivateKey)):
        return "DH", key.key_size, None
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return "EdDSA", 256, "ed25519"
    if isinstance(key, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return "EdDSA", 456, "ed448"
    if isinstance(key, (x25519.X25519PublicKey, x25519.X25519PrivateKey)):
        return "X25519", 256, "x25519"
    if isinstance(key, (x448.X448PublicKey, x448.X448PrivateKey)):
        return "X448", 448, "x448"
    return type(key).__name__, None, None
