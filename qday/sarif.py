"""SARIF 2.1.0 export: one rule per algorithm family, one result per
finding, so code-scanning UIs (GitHub, VS Code) can annotate findings in
place. Code findings carry file:line regions; other assets keep their
location string as the artifact URI."""

from __future__ import annotations

from .risk import remediation

_LEVEL = {"critical": "error", "high": "error", "medium": "warning"}


def export_sarif(rows: list[dict]) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for r in rows:
        rule_id = f"qday-{r['algorithm']}"
        if rule_id not in rules:
            desc = (f"{r['algorithm']} is quantum-vulnerable"
                    if r["quantum_vulnerable"]
                    else f"{r['algorithm']} cryptography inventoried")
            rules[rule_id] = {"id": rule_id,
                              "shortDescription": {"text": desc}}
        fix = remediation(r["algorithm"], r["asset_type"], r["key_size"])
        msg = f"{r['name']}: {r['algorithm']} {r['asset_type']}"
        if r["quantum_vulnerable"]:
            msg += " is quantum-vulnerable"
        if fix:
            msg += f"; migrate to {fix}"
        uri, line = _split_location(r["location"], r["asset_type"])
        physical: dict = {"artifactLocation": {"uri": uri}}
        if line is not None:
            physical["region"] = {"startLine": line}
        results.append({
            "ruleId": rule_id,
            "level": _LEVEL.get(r["risk_level"], "note"),
            "message": {"text": msg},
            "locations": [{"physicalLocation": physical}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "qday",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }


def _split_location(location: str,
                    asset_type: str) -> tuple[str, int | None]:
    """Split a code finding's "path:line" location; other asset types keep
    the raw location (a host:port would false-parse as a line number)."""
    uri = location.replace("\\", "/")
    if asset_type != "code-finding":
        return uri, None
    path, sep, tail = uri.rpartition(":")
    if sep and tail.isdigit():
        return path, int(tail)
    return uri, None
