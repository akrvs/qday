"""qday.toml: reproducible scan targets + human-supplied risk metadata.

    [scan]
    tls   = ["api.example.com:443", "vpn.example.com:8443"]
    certs = ["/etc/ssl"]
    code  = ["../backend"]

    [[annotate]]
    match          = "api.example.com*"   # fnmatch against asset location
    lifespan_years = 25                   # e.g. medical/financial records
    exposure       = "public"

Annotations exist because no scanner can discover how long data must stay
secret or who can reach an asset — that's org knowledge. Committing it to a
config file makes the risk model's human inputs reviewable and versioned.
"""

from __future__ import annotations

import tomllib
from fnmatch import fnmatch
from pathlib import Path

from .model import CryptoAsset, Exposure

DEFAULT_CONFIG = "qday.toml"


class ConfigError(Exception):
    pass


def load_config(path: str | Path) -> dict:
    try:
        with open(path, "rb") as fh:
            doc = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from exc

    scan = doc.get("scan", {})
    annotations = doc.get("annotate", [])
    for ann in annotations:
        if "match" not in ann:
            raise ConfigError(f"{path}: [[annotate]] entry missing 'match'")
        if "exposure" in ann:
            try:
                Exposure(ann["exposure"])
            except ValueError:
                raise ConfigError(
                    f"{path}: exposure must be one of "
                    f"{[e.value for e in Exposure]}, got {ann['exposure']!r}")
    return {
        "tls": list(scan.get("tls", [])),
        "ssh": list(scan.get("ssh", [])),
        "certs": list(scan.get("certs", [])),
        "code": list(scan.get("code", [])),
        "deps": list(scan.get("deps", [])),
        "agility": list(scan.get("agility", [])),
        "annotations": annotations,
    }


def apply_annotations(assets: list[CryptoAsset],
                      annotations: list[dict]) -> int:
    """Mutate assets whose location matches; first matching rule wins per
    field. Returns how many assets were annotated."""
    touched = 0
    for asset in assets:
        hit = False
        lifespan_set = False
        exposure_set = False
        for ann in annotations:
            if not fnmatch(asset.location, ann["match"]):
                continue
            if "lifespan_years" in ann and not lifespan_set:
                asset.data_lifespan_years = int(ann["lifespan_years"])
                lifespan_set = hit = True
            if "exposure" in ann and not exposure_set:
                asset.exposure = Exposure(ann["exposure"])
                exposure_set = hit = True
        touched += hit
    return touched
