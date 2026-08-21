"""AgileKey: key material tagged with the suite that produced it.

The suite travels *with* the key (like a JOSE `alg` or an X.509
AlgorithmIdentifier), so `verify` routes to the right provider automatically
and a keystore can hold RSA and ML-DSA keys side by side during migration
without the caller tracking which is which.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from dataclasses import dataclass


@dataclass(frozen=True)
class AgileKey:
    suite: str
    is_private: bool
    _obj: object  # provider-native key object; opaque to callers

    def to_bytes(self, provider) -> bytes:
        """Serialize to a self-describing envelope. `provider` must be the
        provider for this key's suite (the policy supplies it)."""
        if self.is_private:
            material = provider.serialize_private(self._obj)
        else:
            material = provider.serialize_public(self._obj)
        envelope = {
            "suite": self.suite,
            "private": self.is_private,
            "material": base64.b64encode(material).decode(),
        }
        return json.dumps(envelope).encode()

    def to_file(self, path, provider) -> None:
        mode = 0o600 if self.is_private else 0o644
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)))
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(self.to_bytes(provider))
            os.chmod(tmp, mode)
            os.replace(tmp, path)
        except BaseException:
            os.unlink(tmp)
            raise

    @staticmethod
    def peek_suite(blob: bytes) -> str:
        """Read the suite from an envelope without a provider — this is what
        lets `CryptoPolicy.load_key` pick the right provider to finish."""
        return json.loads(blob)["suite"]

    @classmethod
    def from_bytes(cls, blob: bytes, provider) -> AgileKey:
        env = json.loads(blob)
        if env["suite"] != provider.suite:
            raise ValueError(
                f"envelope suite {env['suite']!r} does not match provider "
                f"{provider.suite!r}")
        material = base64.b64decode(env["material"])
        obj = (provider.load_private(material) if env["private"]
               else provider.load_public(material))
        return cls(suite=env["suite"], is_private=env["private"], _obj=obj)
