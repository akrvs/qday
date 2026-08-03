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
from datetime import date, datetime
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
    waivers = doc.get("waive", [])
    for w in waivers:
        missing = {"match", "reason", "until"} - set(w)
        if missing:
            raise ConfigError(
                f"{path}: [[waive]] entry missing {sorted(missing)}")
        if isinstance(w["until"], str):
            try:
                w["until"] = date.fromisoformat(w["until"])
            except ValueError as exc:
                raise ConfigError(
                    f"{path}: waive until must be a date, "
                    f"got {w['until']!r}") from exc
        elif isinstance(w["until"], datetime):
            w["until"] = w["until"].date()
        elif not isinstance(w["until"], date):
            raise ConfigError(
                f"{path}: waive until must be a date, got {w['until']!r}")

    return {
        "tls": list(scan.get("tls", [])),
        "ssh": list(scan.get("ssh", [])),
        "starttls": list(scan.get("starttls", [])),
        "certs": list(scan.get("certs", [])),
        "code": list(scan.get("code", [])),
        "deps": list(scan.get("deps", [])),
        "agility": list(scan.get("agility", [])),
        "annotations": annotations,
        "waivers": waivers,
    }


def apply_waivers(assets: list[CryptoAsset],
                  scores: dict[str, tuple[float, str]],
                  waivers: list[dict],
                  today: date | None = None) -> int:
    today = today or date.today()
    active = [w for w in waivers if w["until"] >= today]
    waived = 0
    for asset in assets:
        score, level = scores[asset.asset_id]
        if score <= 0:
            continue
        for w in active:
            if fnmatch(asset.location, w["match"]):
                scores[asset.asset_id] = (score, "waived")
                asset.details["waived_reason"] = w["reason"]
                asset.details["waived_until"] = w["until"].isoformat()
                waived += 1
                break
    return waived


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
