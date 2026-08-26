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
        "authorized_private": bool(scan.get("authorized_private")),
        "policy": load_policy(doc),
        "milestones": load_milestones(doc, path),
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


def expired_waiver_hits(assets: list[CryptoAsset],
                        waivers: list[dict],
                        today: date | None = None) -> list[tuple[dict, int]]:
    """Expired waivers that still cover live assets, with hit counts."""
    today = today or date.today()
    hits: list[tuple[dict, int]] = []
    for w in waivers:
        if w["until"] >= today:
            continue
        n = sum(1 for a in assets if fnmatch(a.location, w["match"]))
        if n:
            hits.append((w, n))
    return hits


def load_policy(doc: dict) -> list[str] | None:
    """The [policy] allowed_algorithms list, or None when no policy is set."""
    policy = doc.get("policy", {})
    if not isinstance(policy, dict):
        raise ConfigError("[policy] must be a table")
    allowed = policy.get("allowed_algorithms")
    if allowed is None:
        return None
    if not isinstance(allowed, list) or any(not isinstance(a, str) for a in allowed):
        raise ConfigError("policy.allowed_algorithms must be a list of strings")
    return [a for a in allowed]


def load_milestones(doc: dict, path: str | Path | None = None) -> list[dict]:
    """[[milestone]] entries: date + label markers for the trend charts."""
    milestones = doc.get("milestone", [])
    for m in milestones:
        missing = {"date", "label"} - set(m)
        if missing:
            where = f"{path}: " if path else ""
            raise ConfigError(
                f"{where}[[milestone]] entry missing {sorted(missing)}")
        if isinstance(m["date"], str):
            try:
                m["date"] = date.fromisoformat(m["date"])
            except ValueError as exc:
                where = f"{path}: " if path else ""
                raise ConfigError(
                    f"{where}milestone date must be a date, "
                    f"got {m['date']!r}") from exc
        elif isinstance(m["date"], datetime):
            m["date"] = m["date"].date()
        elif not isinstance(m["date"], date):
            where = f"{path}: " if path else ""
            raise ConfigError(
                f"{where}milestone date must be a date, got {m['date']!r}")
    return milestones


def policy_violations(assets: list[CryptoAsset],
                      scores: dict[str, tuple[float, str]],
                      allowed: list[str]) -> dict[str, int]:
    """Families present on live (scored) assets that the policy does not allow."""
    from .model import canonical_family

    allowed_set = {canonical_family(a) for a in allowed}
    violations: dict[str, int] = {}
    for asset in assets:
        score, _ = scores.get(asset.asset_id, (None, None))
        if score is not None and score <= 0:
            continue
        family = canonical_family(asset.algorithm)
        if family not in allowed_set:
            violations[family] = violations.get(family, 0) + 1
    return violations


def violations_from_rows(rows: list[dict], allowed: list[str]) -> dict[str, int]:
    """Same check for stored rows (risk_score already persisted)."""
    from .model import canonical_family

    allowed_set = {canonical_family(a) for a in allowed}
    violations: dict[str, int] = {}
    for r in rows:
        if r["risk_score"] is not None and r["risk_score"] <= 0:
            continue
        family = canonical_family(r["algorithm"])
        if family not in allowed_set:
            violations[family] = violations.get(family, 0) + 1
    return violations


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
