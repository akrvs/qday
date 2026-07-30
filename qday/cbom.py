"""CycloneDX 1.6 CBOM export and import.

Emits and parses the JSON directly against the 1.6 schema's
`cryptographic-asset` component type rather than pulling in a BOM library —
the surface we need is small and this keeps the dependency tree short for a
security tool.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from . import __version__
from .model import AssetType, CryptoAsset, Exposure, known_family

# Our asset types → CycloneDX cryptoProperties.assetType
_CDX_ASSET_TYPE = {
    "certificate": "certificate",
    "key-material": "related-crypto-material",
    "tls-endpoint": "protocol",
    "ssh-endpoint": "protocol",
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


_ASSET_TYPE_FROM_CDX = {
    "certificate": AssetType.CERTIFICATE,
    "related-crypto-material": AssetType.KEY_MATERIAL,
    "protocol": AssetType.TLS_ENDPOINT,
    "algorithm": AssetType.CODE_FINDING,
}


def import_cbom(doc: dict) -> list[CryptoAsset]:
    """Parse a CycloneDX BOM — ours or another tool's — into CryptoAssets.
    Forgiving like the manifest parsers: missing fields degrade to
    conservative defaults instead of failing the import."""
    if doc.get("bomFormat") != "CycloneDX":
        raise ValueError("not a CycloneDX document (bomFormat missing)")
    assets = []
    for comp in doc.get("components") or []:
        if comp.get("type") != "cryptographic-asset":
            continue
        crypto = comp.get("cryptoProperties") or {}
        algo = crypto.get("algorithmProperties") or {}
        props = {p.get("name"): p.get("value")
                 for p in comp.get("properties") or []}
        name = str(comp.get("name") or "imported-asset")
        occurrences = (comp.get("evidence") or {}).get("occurrences") or []
        location = name
        if occurrences:
            location = str(occurrences[0].get("location") or name)
        param = str(algo.get("parameterSetIdentifier") or "")
        try:
            exposure = Exposure(props.get("qday:exposure", "local"))
        except ValueError:
            exposure = Exposure.LOCAL
        try:
            lifespan = int(props.get("qday:data_lifespan_years", 10))
        except (TypeError, ValueError):
            lifespan = 10
        assets.append(CryptoAsset(
            name=name,
            asset_type=_ASSET_TYPE_FROM_CDX.get(crypto.get("assetType"),
                                                AssetType.CODE_FINDING),
            algorithm=(props.get("qday:algorithm_family")
                       or known_family(name) or name),
            key_size=int(param) if param.isdigit() else None,
            curve=algo.get("curve"),
            location=location,
            scanner="import",
            exposure=exposure,
            data_lifespan_years=lifespan,
            details={"imported": True, "bom_ref": comp.get("bom-ref", "")},
        ))
    return assets


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
