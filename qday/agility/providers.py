"""Signature providers: one class per algorithm suite, behind a uniform
interface so the rest of the layer never imports a concrete algorithm.

A provider owns everything algorithm-specific — key generation, sign/verify,
and its own serialization format — so adding a suite (including a PQC one)
never touches the policy engine or application code. That is the whole point
of crypto-agility: the swap is a registry entry, not a rewrite.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec, ed448, ed25519, padding, rsa,
)

_PEM = serialization.Encoding.PEM
_PKCS8 = serialization.PrivateFormat.PKCS8
_SPKI = serialization.PublicFormat.SubjectPublicKeyInfo
_NOENC = serialization.NoEncryption()


@runtime_checkable
class SignatureProvider(Protocol):
    suite: str      # canonical suite id, e.g. "ed25519"
    family: str     # algorithm family for inventory, e.g. "EdDSA"
    quantum_safe: bool

    def generate(self): ...
    def sign(self, private_obj, data: bytes) -> bytes: ...
    def verify(self, public_obj, data: bytes, signature: bytes) -> bool: ...
    def serialize_private(self, private_obj) -> bytes: ...
    def load_private(self, blob: bytes): ...
    def serialize_public(self, public_obj) -> bytes: ...
    def load_public(self, blob: bytes): ...


class _CryptographyProvider:
    """Shared serialization for suites backed by `cryptography` key objects."""

    quantum_safe = False

    def serialize_private(self, private_obj) -> bytes:
        return private_obj.private_bytes(_PEM, _PKCS8, _NOENC)

    def load_private(self, blob: bytes):
        return serialization.load_pem_private_key(blob, password=None)

    def serialize_public(self, public_obj) -> bytes:
        return public_obj.public_bytes(_PEM, _SPKI)

    def load_public(self, blob: bytes):
        return serialization.load_pem_public_key(blob)


class RSAProvider(_CryptographyProvider):
    family = "RSA"

    def __init__(self, key_size: int):
        self.key_size = key_size
        self.suite = f"rsa-{key_size}"

    def generate(self):
        return rsa.generate_private_key(public_exponent=65537,
                                        key_size=self.key_size)

    def sign(self, private_obj, data: bytes) -> bytes:
        return private_obj.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())

    def verify(self, public_obj, data: bytes, signature: bytes) -> bool:
        try:
            public_obj.verify(
                signature, data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())
            return True
        except InvalidSignature:
            return False


class ECDSAProvider(_CryptographyProvider):
    family = "ECDSA"
    _CURVES = {"p256": ec.SECP256R1, "p384": ec.SECP384R1,
               "p521": ec.SECP521R1}

    def __init__(self, curve: str):
        if curve not in self._CURVES:
            raise ValueError(f"unknown ECDSA curve {curve!r}")
        self.curve = curve
        self.suite = f"ecdsa-{curve}"

    def generate(self):
        return ec.generate_private_key(self._CURVES[self.curve]())

    def sign(self, private_obj, data: bytes) -> bytes:
        return private_obj.sign(data, ec.ECDSA(hashes.SHA256()))

    def verify(self, public_obj, data: bytes, signature: bytes) -> bool:
        try:
            public_obj.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False


class _EdProvider(_CryptographyProvider):
    family = "EdDSA"
    _private_cls = None

    def sign(self, private_obj, data: bytes) -> bytes:
        return private_obj.sign(data)

    def verify(self, public_obj, data: bytes, signature: bytes) -> bool:
        try:
            public_obj.verify(signature, data)
            return True
        except InvalidSignature:
            return False


class Ed25519Provider(_EdProvider):
    suite = "ed25519"

    def generate(self):
        return ed25519.Ed25519PrivateKey.generate()


class Ed448Provider(_EdProvider):
    suite = "ed448"

    def generate(self):
        return ed448.Ed448PrivateKey.generate()


class MLDSAProvider:
    """NIST ML-DSA (FIPS 204) via the optional `oqs` backend (liboqs).

    The suite is fully wired even when the backend is absent — that is the
    migration promise: `pip install oqs` turns the config binding live with
    zero application changes. Without it, only key generation / signing raise,
    and only when actually invoked.
    """

    quantum_safe = True
    family = "ML-DSA"
    _MECHANISM = {"ml-dsa-44": "Dilithium2", "ml-dsa-65": "Dilithium3",
                  "ml-dsa-87": "Dilithium5"}

    def __init__(self, level: str):
        if level not in self._MECHANISM:
            raise ValueError(f"unknown ML-DSA level {level!r}")
        self.suite = level
        self._mechanism = self._MECHANISM[level]

    def _backend(self):
        try:
            import oqs  # noqa: PLC0415 (optional dependency)
        except ImportError as exc:
            raise BackendUnavailable(
                f"{self.suite} needs the 'oqs' package (liboqs). "
                "Install it to activate post-quantum signing.") from exc
        return oqs

    def generate(self):
        oqs = self._backend()
        signer = oqs.Signature(self._mechanism)
        public = signer.generate_keypair()
        secret = signer.export_secret_key()
        return _OQSKeyPair(self._mechanism, secret, public)

    def sign(self, private_obj, data: bytes) -> bytes:
        oqs = self._backend()
        with oqs.Signature(self._mechanism, private_obj.secret) as signer:
            return signer.sign(data)

    def verify(self, public_obj, data: bytes, signature: bytes) -> bool:
        oqs = self._backend()
        with oqs.Signature(self._mechanism) as verifier:
            return bool(verifier.verify(data, signature, public_obj.public))

    def serialize_private(self, private_obj) -> bytes:
        return private_obj.secret

    def load_private(self, blob: bytes):
        return _OQSKeyPair(self._mechanism, blob, None)

    def serialize_public(self, public_obj) -> bytes:
        return public_obj.public

    def load_public(self, blob: bytes):
        return _OQSKeyPair(self._mechanism, None, blob)


class _OQSKeyPair:
    """Byte-string key holder for the oqs backend (which is stateless per op)."""

    def __init__(self, mechanism: str, secret: bytes | None,
                 public: bytes | None):
        self.mechanism = mechanism
        self.secret = secret
        self.public = public


class HybridProvider:
    """Composite signature: sign with both arms, require BOTH to verify.

    This is how migration actually happens (CNSA 2.0 hybrids): a classical
    arm the world already trusts plus a PQC arm, so the signature holds as
    long as *either* algorithm is unbroken. Neither arm alone is sufficient
    to forge, so the combined signature is no weaker than the stronger arm.
    """

    family = "hybrid"

    def __init__(self, first: SignatureProvider, second: SignatureProvider):
        self.first = first
        self.second = second
        self.suite = f"hybrid:{first.suite}+{second.suite}"
        # Hybrid is quantum-safe only if at least one arm is.
        self.quantum_safe = first.quantum_safe or second.quantum_safe

    def generate(self):
        return _Pair(self.first.generate(), self.second.generate())

    def sign(self, private_obj, data: bytes) -> bytes:
        return _frame([self.first.sign(private_obj.a, data),
                       self.second.sign(private_obj.b, data)])

    def verify(self, public_obj, data: bytes, signature: bytes) -> bool:
        try:
            sig_a, sig_b = _unframe(signature)
        except ValueError:
            return False
        return (self.first.verify(public_obj.a, data, sig_a)
                and self.second.verify(public_obj.b, data, sig_b))

    def serialize_private(self, private_obj) -> bytes:
        return _frame([self.first.serialize_private(private_obj.a),
                       self.second.serialize_private(private_obj.b)])

    def load_private(self, blob: bytes):
        a, b = _unframe(blob)
        return _Pair(self.first.load_private(a), self.second.load_private(b))

    def serialize_public(self, public_obj) -> bytes:
        return _frame([self.first.serialize_public(public_obj.a),
                       self.second.serialize_public(public_obj.b)])

    def load_public(self, blob: bytes):
        a, b = _unframe(blob)
        return _Pair(self.first.load_public(a), self.second.load_public(b))


class _Pair:
    __slots__ = ("a", "b")

    def __init__(self, a, b):
        self.a = a
        self.b = b


def _frame(parts: list[bytes]) -> bytes:
    """Length-prefixed concatenation: 4-byte big-endian length + payload."""
    out = bytearray()
    for p in parts:
        out += len(p).to_bytes(4, "big") + p
    return bytes(out)


def _unframe(blob: bytes) -> list[bytes]:
    parts, i = [], 0
    while i < len(blob):
        (n,) = (int.from_bytes(blob[i:i + 4], "big"),)
        i += 4
        if i + n > len(blob):
            raise ValueError("truncated framed payload")
        parts.append(blob[i:i + n])
        i += n
    if len(parts) != 2:
        raise ValueError(f"expected 2 framed parts, got {len(parts)}")
    return parts


class BackendUnavailable(RuntimeError):
    """Raised when a suite's optional backend isn't installed."""
