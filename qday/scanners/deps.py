"""Dependency-manifest scanner.

Catches crypto that lives in third-party libraries — the code scanner only
sees first-party source, so a service that signs JWTs entirely through
`jsonwebtoken` shows up here and nowhere else. Each ecosystem has a small
parser that yields (package_name, version, manifest-relative-path); names are
matched against the catalog in rules/dependencies.yaml.

Parsers are intentionally forgiving: a manifest we can't fully parse should
degrade to "found fewer packages", never crash a scan.
"""

from __future__ import annotations

import json
import re
import tomllib
from importlib import resources
from pathlib import Path
from typing import Iterator
from xml.etree import ElementTree

import yaml

from ..model import AssetType, CryptoAsset, Exposure

_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__",
              "dist", "build", "vendor", ".tox", "target"}
_MAX_FILE_BYTES = 5_000_000


def load_catalog() -> dict[str, dict[str, str]]:
    path = resources.files("qday.scanners") / "rules" / "dependencies.yaml"
    return yaml.safe_load(path.read_text())


class DepScanner:
    name = "deps"

    # manifest filename -> (ecosystem, parser method name)
    _MANIFESTS = {
        "requirements.txt": ("pypi", "_parse_requirements"),
        "poetry.lock": ("pypi", "_parse_poetry_lock"),
        "package-lock.json": ("npm", "_parse_package_lock"),
        "package.json": ("npm", "_parse_package_json"),
        "go.mod": ("go", "_parse_go_mod"),
        "Cargo.lock": ("cargo", "_parse_cargo_lock"),
        "Cargo.toml": ("cargo", "_parse_cargo_toml"),
        "pom.xml": ("maven", "_parse_pom"),
    }

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self._catalog = load_catalog()

    def scan(self) -> Iterator[CryptoAsset]:
        for path in sorted(self.root.rglob("*")):
            spec = self._MANIFESTS.get(path.name)
            if spec is None or not path.is_file():
                continue
            if _SKIP_DIRS.intersection(path.parts[:-1]):
                continue
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            ecosystem, parser_name = spec
            catalog = self._catalog.get(ecosystem, {})
            rel = str(path.relative_to(self.root))
            try:
                packages = getattr(self, parser_name)(path)
            except (ValueError, OSError, ElementTree.ParseError,
                    tomllib.TOMLDecodeError, json.JSONDecodeError):
                continue
            for pkg, version in packages:
                family = _catalog_match(catalog, pkg, ecosystem)
                if family is None:
                    continue
                yield CryptoAsset(
                    name=f"{pkg}{('@' + version) if version else ''}",
                    asset_type=AssetType.DEPENDENCY,
                    algorithm=family,
                    location=f"{rel}#{pkg}",
                    scanner=self.name,
                    exposure=Exposure.LOCAL,
                    details={"ecosystem": ecosystem, "package": pkg,
                             "version": version or "unpinned",
                             "note": "crypto provided by a third-party "
                                     "dependency (transitive-capable)"},
                )

    # --- parsers: each returns list[(name, version|None)] -----------------

    def _parse_requirements(self, path: Path) -> list[tuple[str, str | None]]:
        out = []
        for line in path.read_text(errors="ignore").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            m = re.match(r"([A-Za-z0-9._-]+)\s*(?:==|>=|~=|>)?\s*([\w.]+)?",
                         line)
            if m:
                out.append((m.group(1).lower(), m.group(2)))
        return out

    def _parse_poetry_lock(self, path: Path) -> list[tuple[str, str | None]]:
        doc = tomllib.loads(path.read_text())
        return [(p.get("name", "").lower(), p.get("version"))
                for p in doc.get("package", [])]

    def _parse_package_lock(self, path: Path) -> list[tuple[str, str | None]]:
        doc = json.loads(path.read_text())
        out = []
        # npm v7+ lockfile: keyed by "node_modules/<name>"
        for key, meta in (doc.get("packages") or {}).items():
            if not key:
                continue
            name = key.split("node_modules/")[-1]
            out.append((name, meta.get("version")))
        # v6 fallback
        for name, meta in (doc.get("dependencies") or {}).items():
            out.append((name, meta.get("version")))
        return out

    def _parse_package_json(self, path: Path) -> list[tuple[str, str | None]]:
        doc = json.loads(path.read_text())
        out = []
        for section in ("dependencies", "devDependencies"):
            for name, ver in (doc.get(section) or {}).items():
                out.append((name, str(ver)))
        return out

    def _parse_go_mod(self, path: Path) -> list[tuple[str, str | None]]:
        out = []
        for line in path.read_text(errors="ignore").splitlines():
            m = re.search(r"([\w./-]+)\s+(v[\w.\-+]+)", line.strip())
            if m and not line.strip().startswith(("module", "go ")):
                out.append((m.group(1), m.group(2)))
        return out

    def _parse_cargo_lock(self, path: Path) -> list[tuple[str, str | None]]:
        doc = tomllib.loads(path.read_text())
        return [(p.get("name", ""), p.get("version"))
                for p in doc.get("package", [])]

    def _parse_cargo_toml(self, path: Path) -> list[tuple[str, str | None]]:
        doc = tomllib.loads(path.read_text())
        out = []
        for section in ("dependencies", "dev-dependencies"):
            for name, spec in (doc.get(section) or {}).items():
                ver = spec if isinstance(spec, str) else spec.get("version")
                out.append((name, ver))
        return out

    def _parse_pom(self, path: Path) -> list[tuple[str, str | None]]:
        # Strip the default namespace so tag lookups don't need the URI.
        text = re.sub(r'\sxmlns="[^"]+"', "", path.read_text(), count=1)
        root = ElementTree.fromstring(text)
        out = []
        for dep in root.iter("dependency"):
            gid = dep.findtext("groupId", "")
            aid = dep.findtext("artifactId", "")
            ver = dep.findtext("version")
            out.append((f"{gid}:{aid}", ver))
        return out


def _catalog_match(catalog: dict[str, str], pkg: str,
                   ecosystem: str) -> str | None:
    """Exact match, then prefix match for path/group-style names (Go import
    paths, Maven groupId:artifactId)."""
    if pkg in catalog:
        return catalog[pkg]
    if ecosystem in ("go", "maven"):
        for known, family in catalog.items():
            if pkg == known or pkg.startswith(known + ("/" if ecosystem == "go"
                                                       else ":")):
                return family
    return None
