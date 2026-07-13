"""Rule-driven source-code scanner.

Deliberately breadth-over-depth: regex rules over source lines, per
language, defined in rules/*.yaml. It will not follow dataflow the way
CodeQL does — its job is inventory coverage across many languages and
repos cheaply, with file:line evidence for a human to triage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Iterator

import yaml

from ..model import AssetType, CryptoAsset, Exposure

_SKIP_DIRS = {".git", ".svn", ".venv", "venv", "node_modules",
              "__pycache__", "dist", "build", "vendor", ".tox"}
_MAX_FILE_BYTES = 2_000_000
# How many lines after a match to search for a key-size argument that
# spilled onto the next line(s).
_KEY_SIZE_LOOKAHEAD = 3


@dataclass
class Rule:
    id: str
    pattern: re.Pattern
    algorithm: str
    key_size_pattern: re.Pattern | None
    note: str | None
    language: str
    keywords: tuple[str, ...]  # lowercase literals; any-of gates the regex


def load_rules() -> tuple[dict[str, list[Rule]], list[Rule]]:
    """Return (rules by file extension, generic rules for all files)."""
    by_ext: dict[str, list[Rule]] = {}
    generic: list[Rule] = []
    rule_dir = resources.files("qday.scanners") / "rules"
    for entry in sorted(rule_dir.iterdir(), key=lambda e: e.name):
        if not entry.name.endswith(".yaml"):
            continue
        doc = yaml.safe_load(entry.read_text())
        rules = [
            Rule(
                id=r["id"],
                pattern=re.compile(r["pattern"]),
                algorithm=r["algorithm"],
                key_size_pattern=(re.compile(r["key_size_pattern"])
                                  if r.get("key_size_pattern") else None),
                note=r.get("note"),
                language=doc["language"],
                keywords=tuple(r["keywords"]),  # required: no keywords means
                                                # the rule would never fire
            )
            for r in doc["rules"]
        ]
        if doc["file_extensions"] == ["*"]:
            generic.extend(rules)
        else:
            for ext in doc["file_extensions"]:
                by_ext.setdefault(ext, []).extend(rules)
    return by_ext, generic


class CodeScanner:
    name = "code"

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self._by_ext, self._generic = load_rules()

    def scan(self) -> Iterator[CryptoAsset]:
        for path in sorted(self.root.rglob("*")):
            if _SKIP_DIRS.intersection(path.parts) or not path.is_file():
                continue
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            rules = self._by_ext.get(path.suffix.lower(), []) + self._generic
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            # Keyword prescreen: str.find runs at C speed, so files with no
            # crypto tell-tales (almost all of them) never reach the regex
            # engine or the per-line loop.
            low = text.lower()
            active = [r for r in rules
                      if any(k in low for k in r.keywords)]
            if not active:
                continue
            yield from self._scan_lines(path, text.splitlines(), active)

    def _scan_lines(self, path: Path, lines: list[str],
                    rules: list[Rule]) -> Iterator[CryptoAsset]:
        rel = str(path.relative_to(self.root))
        for lineno, line in enumerate(lines, start=1):
            for rule in rules:
                if not rule.pattern.search(line):
                    continue
                key_size = _find_key_size(rule, lines, lineno)
                details = {"rule": rule.id, "language": rule.language,
                           "match": line.strip()[:200]}
                if rule.note:
                    details["note"] = rule.note
                yield CryptoAsset(
                    name=f"{rule.algorithm} usage ({rule.id})",
                    asset_type=AssetType.CODE_FINDING,
                    algorithm=rule.algorithm,
                    key_size=key_size,
                    location=f"{rel}:{lineno}",
                    scanner=self.name,
                    exposure=Exposure.LOCAL,
                    details=details,
                )


def _find_key_size(rule: Rule, lines: list[str], lineno: int) -> int | None:
    if rule.key_size_pattern is None:
        return None
    window = lines[lineno - 1:lineno - 1 + _KEY_SIZE_LOOKAHEAD]
    for candidate in window:
        m = rule.key_size_pattern.search(candidate)
        if m:
            return int(m.group(1))
    return None
