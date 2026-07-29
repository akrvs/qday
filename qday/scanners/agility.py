"""Agility-policy scanner: inventory a crypto-agility config as CryptoAssets.

Closes the loop — the policy that governs your migration is itself crypto
that belongs in the CBOM. A purpose still bound to a quantum-vulnerable suite
is exactly the migration work QDAY exists to track, and now it shows up beside
the certs and code findings on the same dashboard.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from ..agility import CryptoPolicy, PolicyError
from ..model import AssetType, CryptoAsset, Exposure


class AgilityScanner:
    name = "agility"

    def __init__(self, policy_path: str | Path):
        self.policy_path = Path(policy_path)

    def scan(self) -> Iterator[CryptoAsset]:
        try:
            policy = CryptoPolicy.from_file(self.policy_path)
        except (OSError, PolicyError):
            return
        rel = self.policy_path.name
        for row in policy.inventory():
            # A quantum-safe hybrid has no family of its own; map it to its
            # PQC arm's family so downstream classification counts it safe.
            algorithm = row["family"]
            if algorithm == "hybrid" and row["quantum_safe"]:
                algorithm = "ML-DSA"
            yield CryptoAsset(
                name=f"policy purpose '{row['purpose']}' -> {row['suite']}",
                asset_type=AssetType.CODE_FINDING,
                algorithm=algorithm,
                location=f"{rel}#{row['purpose']}",
                scanner=self.name,
                exposure=Exposure.LOCAL,
                details={"suite": row["suite"], "purpose": row["purpose"],
                         "deprecated": row["deprecated"],
                         "quantum_safe": row["quantum_safe"],
                         "note": "crypto-agility policy binding"},
            )
