"""Crypto-agility layer: bind algorithm choice to config, not code.

    from qday.agility import CryptoPolicy

    policy = CryptoPolicy.from_file("agility.toml")
    priv, pub = policy.generate("firmware-signing")
    sig = policy.sign(priv, firmware_bytes)
    assert policy.verify(pub, firmware_bytes, sig)

Migrating "firmware-signing" from ed25519 to a PQC hybrid is a one-line edit
in agility.toml; none of the code above changes.
"""

from .keys import AgileKey
from .policy import (
    CryptoPolicy,
    DeprecatedSuiteError,
    PolicyError,
    build_provider,
)
from .providers import BackendUnavailable

__all__ = [
    "AgileKey",
    "CryptoPolicy",
    "DeprecatedSuiteError",
    "PolicyError",
    "BackendUnavailable",
    "build_provider",
]
