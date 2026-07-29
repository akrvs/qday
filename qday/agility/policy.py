"""CryptoPolicy: the one object application code talks to.

Application code names a *purpose* ("firmware-signing"); the policy file binds
that purpose to a *suite* ("ed25519", "ml-dsa-65", "hybrid:ed25519+ml-dsa-65").
Migrating to post-quantum is editing that binding — the code that calls
`policy.sign(key, data)` never changes, and old keys keep verifying because
their provider stays registered.

    [purposes]
    document-signing = "rsa-3072"
    firmware-signing = "hybrid:ed25519+ml-dsa-65"

    [policy]
    deprecated = ["rsa-2048", "ecdsa-p256"]   # refuse NEW keys with these
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from .keys import AgileKey
from .providers import (
    ECDSAProvider,
    Ed448Provider,
    Ed25519Provider,
    HybridProvider,
    MLDSAProvider,
    MLKEMProvider,
    RSAProvider,
    SignatureProvider,
)

Provider = SignatureProvider | MLKEMProvider


class PolicyError(Exception):
    pass


class DeprecatedSuiteError(PolicyError):
    """Raised when a purpose is bound to a suite the policy forbids for new
    keys — the guard rail that stops migration from silently regressing."""


def build_provider(suite: str) -> Provider:
    """Construct a provider from a suite id. `hybrid:a+b` composes two."""
    if suite.startswith("hybrid:"):
        body = suite[len("hybrid:"):]
        if "+" not in body:
            raise PolicyError(f"hybrid suite must be 'hybrid:a+b', got {suite!r}")
        first, second = body.split("+", 1)
        arms = (build_provider(first), build_provider(second))
        if not all(hasattr(p, "sign") for p in arms):
            raise PolicyError(
                f"hybrid arms must be signature suites, got {suite!r}")
        return HybridProvider(*arms)
    if suite.startswith("ml-kem-"):
        return MLKEMProvider(suite)
    if suite.startswith("rsa-"):
        return RSAProvider(int(suite.split("-", 1)[1]))
    if suite.startswith("ecdsa-"):
        return ECDSAProvider(suite.split("-", 1)[1])
    if suite == "ed25519":
        return Ed25519Provider()
    if suite == "ed448":
        return Ed448Provider()
    if suite.startswith("ml-dsa-"):
        return MLDSAProvider(suite)
    raise PolicyError(f"unknown suite {suite!r}")


class CryptoPolicy:
    def __init__(self, purposes: dict[str, str],
                 deprecated: list[str] | None = None):
        self.purposes = dict(purposes)
        self.deprecated = set(deprecated or [])
        # One provider instance per distinct suite in play (purposes may share).
        self._providers: dict[str, Provider] = {}
        for suite in self.purposes.values():
            self._provider_for(suite)

    @classmethod
    def from_file(cls, path: str | Path) -> CryptoPolicy:
        with open(path, "rb") as fh:
            doc = tomllib.load(fh)
        # Accept either a standalone file or an [agility] block in qday.toml.
        root = doc.get("agility", doc)
        purposes = root.get("purposes", {})
        if not purposes:
            raise PolicyError(f"{path}: no [purposes] defined")
        deprecated = root.get("policy", {}).get("deprecated", [])
        return cls(purposes, deprecated)

    def _provider_for(self, suite: str) -> Provider:
        if suite not in self._providers:
            self._providers[suite] = build_provider(suite)
        return self._providers[suite]

    # --- application API --------------------------------------------------

    def generate(self, purpose: str) -> tuple[AgileKey, AgileKey]:
        """New keypair for a purpose, using its current suite binding.
        Refuses deprecated suites — new keys must not regress."""
        suite = self.purposes.get(purpose)
        if suite is None:
            raise PolicyError(f"unknown purpose {purpose!r}; known: "
                              f"{sorted(self.purposes)}")
        if suite in self.deprecated:
            raise DeprecatedSuiteError(
                f"purpose {purpose!r} is bound to deprecated suite {suite!r}; "
                "update the policy before issuing new keys")
        provider = self._provider_for(suite)
        private_obj = provider.generate()
        public_obj = _public_of(provider, private_obj)
        return (AgileKey(suite, True, private_obj),
                AgileKey(suite, False, public_obj))

    def sign(self, private_key: AgileKey, data: bytes) -> bytes:
        if not private_key.is_private:
            raise PolicyError("sign requires a private key")
        provider = self._signature_provider(private_key.suite)
        return provider.sign(private_key._obj, data)

    def verify(self, public_key: AgileKey, data: bytes,
               signature: bytes) -> bool:
        provider = self._signature_provider(public_key.suite)
        return provider.verify(public_key._obj, data, signature)

    def encapsulate(self, public_key: AgileKey) -> tuple[bytes, bytes]:
        """Return (ciphertext, shared_secret) against the peer's public key;
        the peer recovers the secret with decapsulate."""
        provider = self._kem_provider(public_key.suite)
        return provider.encapsulate(public_key._obj)

    def decapsulate(self, private_key: AgileKey,
                    ciphertext: bytes) -> bytes:
        if not private_key.is_private:
            raise PolicyError("decapsulate requires a private key")
        provider = self._kem_provider(private_key.suite)
        return provider.decapsulate(private_key._obj, ciphertext)

    def _signature_provider(self, suite: str) -> SignatureProvider:
        provider = self._provider_for(suite)
        if not hasattr(provider, "sign"):
            raise PolicyError(f"suite {suite!r} is a KEM; use "
                              "encapsulate/decapsulate")
        return provider

    def _kem_provider(self, suite: str) -> MLKEMProvider:
        provider = self._provider_for(suite)
        if not hasattr(provider, "encapsulate"):
            raise PolicyError(f"suite {suite!r} is not a KEM")
        return provider

    def serialize_key(self, key: AgileKey) -> bytes:
        return key.to_bytes(self._provider_for(key.suite))

    def load_key(self, blob: bytes) -> AgileKey:
        """Deserialize an envelope, auto-selecting the provider from its
        embedded suite — the caller never states the algorithm."""
        suite = AgileKey.peek_suite(blob)
        return AgileKey.from_bytes(blob, self._provider_for(suite))

    # --- introspection (dogfooded by the scanner) -------------------------

    def inventory(self) -> list[dict]:
        """Every purpose→suite binding with its quantum posture. This is what
        lets QDAY scan its own agility policy into the CBOM."""
        out = []
        for purpose, suite in sorted(self.purposes.items()):
            provider = self._provider_for(suite)
            out.append({
                "purpose": purpose,
                "suite": suite,
                "family": provider.family,
                "quantum_safe": bool(provider.quantum_safe),
                "deprecated": suite in self.deprecated,
            })
        return out


def _public_of(provider: SignatureProvider, private_obj):
    """Derive the public object from a freshly generated private object."""
    if hasattr(private_obj, "public_key"):
        return private_obj.public_key()
    if hasattr(private_obj, "a"):  # hybrid _Pair
        return type(private_obj)(_public_of(provider.first, private_obj.a),
                                 _public_of(provider.second, private_obj.b))
    if hasattr(private_obj, "public") or hasattr(private_obj, "secret"):
        # oqs keypair holds both halves already.
        return private_obj
    raise PolicyError(f"cannot derive public key for {provider.suite}")
