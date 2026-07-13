"""CycloneDX 1.6 CBOM export.

Emits the JSON directly against the 1.6 schema's `cryptographic-asset`
component type rather than pulling in a BOM library — the surface we need
is small and this keeps the dependency tree short for a security tool.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from . import __version__

# Our asset types → CycloneDX cryptoProperties.assetType
_CDX_ASSET_TYPE = {
    "certificate": "certificate",
    "key-material": "related-crypto-material",
    "tls-endpoint": "protocol",
    "code-finding": "algorithm",
    "dependency": "algorithm",
}

# Shor-broken families get NIST quantum security level 0.
_PRIMITIVE = {
    "RSA": "pke", "EC": "pke", "ECDH": "key-agree", "DH": "key-agree",
    "X25519": "key-agree", "X448": "key-agree",
    "ECDSA": "signature", "DSA": "signature", "EdDSA": "signature",
    "ML-DSA": "signature", "SLH-DSA": "signature", "FN-DSA": "signature",
    "ML-KEM": "kem", "AES": "block-cipher", "CHACHA20": "stream-cipher",
}


def export_cbom(rows: list[dict], run_info: dict | None) -> dict:
    """Build a CycloneDX 1.6 BOM dict from stored asset rows."""
    components = [_component(r) for r in rows]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc)
                .isoformat(timespec="seconds"),
            "tools": {"components": [{
                "type": "application", "name": "qday",
                "version": __version__,
            }]},
            "properties": ([{"name": "qday:run_label",
                             "value": run_info["label"]}]
                           if run_info and run_info.get("label") else []),
        },
        "components": components,
    }


def _component(row: dict) -> dict:
    details = json.loads(row.get("details_json") or "{}")
    quantum_level = 0 if row["quantum_vulnerable"] else None

    algo_props: dict = {"primitive": _PRIMITIVE.get(row["algorithm"], "other")}
    if row.get("key_size"):
        algo_props["parameterSetIdentifier"] = str(row["key_size"])
    if row.get("curve"):
        algo_props["curve"] = row["curve"]
    if quantum_level is not None:
        algo_props["nistQuantumSecurityLevel"] = quantum_level

    crypto_props: dict = {
        "assetType": _CDX_ASSET_TYPE.get(row["asset_type"], "algorithm"),
        "oid": details.get("oid", ""),
    }
    if crypto_props["assetType"] == "certificate":
        crypto_props["certificateProperties"] = {
            "issuerName": details.get("issuer", ""),
            "notValidAfter": details.get("not_after", ""),
            "signatureAlgorithmRef": details.get("signature_algorithm", ""),
            "subjectPublicKeyRef": row["algorithm"],
        }
    elif crypto_props["assetType"] == "protocol":
        crypto_props["protocolProperties"] = {
            "type": "tls",
            "version": details.get("tls_version", ""),
        }
    else:
        crypto_props["algorithmProperties"] = algo_props
    crypto_props = {k: v for k, v in crypto_props.items() if v != ""}

    return {
        "type": "cryptographic-asset",
        "bom-ref": row["asset_id"],
        "name": row["name"],
        "evidence": {"occurrences": [{"location": row["location"]}]},
        "cryptoProperties": crypto_props,
        "properties": [
            {"name": "qday:algorithm_family", "value": row["algorithm"]},
            {"name": "qday:quantum_vulnerable",
             "value": str(bool(row["quantum_vulnerable"])).lower()},
            {"name": "qday:risk_score",
             "value": str(row.get("risk_score"))},
            {"name": "qday:risk_level",
             "value": str(row.get("risk_level"))},
            {"name": "qday:exposure", "value": row["exposure"]},
            {"name": "qday:data_lifespan_years",
             "value": str(row["data_lifespan_years"])},
        ],
    }
