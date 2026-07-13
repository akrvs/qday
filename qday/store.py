"""SQLite persistence: every scan is a timestamped run, so "continuous"
means append runs and diff them — no server required."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .model import CryptoAsset

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    label TEXT
);
CREATE TABLE IF NOT EXISTS assets (
    run_id INTEGER NOT NULL REFERENCES runs(id),
    asset_id TEXT NOT NULL,
    name TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    key_size INTEGER,
    curve TEXT,
    location TEXT NOT NULL,
    scanner TEXT NOT NULL,
    exposure TEXT NOT NULL,
    data_lifespan_years INTEGER NOT NULL,
    quantum_vulnerable INTEGER NOT NULL,
    risk_score REAL,
    risk_level TEXT,
    details_json TEXT NOT NULL,
    PRIMARY KEY (run_id, asset_id)
);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._con = sqlite3.connect(self.path)
        self._con.row_factory = sqlite3.Row
        self._con.executescript(_SCHEMA)

    def close(self) -> None:
        self._con.close()

    def save_run(self, assets: list[CryptoAsset],
                 scores: dict[str, tuple[float, str]] | None = None,
                 label: str | None = None) -> int:
        """Persist one scan run. `scores` maps asset_id -> (score, level)."""
        scores = scores or {}
        cur = self._con.execute(
            "INSERT INTO runs (started_at, label) VALUES (?, ?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), label),
        )
        run_id = cur.lastrowid
        for a in assets:
            row = a.to_row()
            score, level = scores.get(row["asset_id"], (None, None))
            row.update({"run_id": run_id, "risk_score": score,
                        "risk_level": level})
            cols = ", ".join(row)
            ph = ", ".join(f":{k}" for k in row)
            # ON CONFLICT: two scanners may legitimately see the same asset
            # (e.g. a cert on disk and the same cert served over TLS from
            # the same location string); keep the first sighting.
            self._con.execute(
                f"INSERT OR IGNORE INTO assets ({cols}) VALUES ({ph})", row)
        self._con.commit()
        return run_id

    def latest_run_id(self) -> int | None:
        row = self._con.execute("SELECT MAX(id) AS id FROM runs").fetchone()
        return row["id"]

    def run_info(self, run_id: int) -> dict | None:
        row = self._con.execute(
            "SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return dict(row) if row else None

    def assets_for_run(self, run_id: int) -> list[dict]:
        rows = self._con.execute(
            "SELECT * FROM assets WHERE run_id = ? "
            "ORDER BY risk_score DESC, algorithm", (run_id,)).fetchall()
        return [dict(r) for r in rows]

    def diff_runs(self, from_id: int, to_id: int) -> dict[str, list[dict]]:
        """Assets that appeared, disappeared, or persisted between two runs,
        keyed by the stable asset_id."""
        old = {r["asset_id"]: r for r in self.assets_for_run(from_id)}
        new = {r["asset_id"]: r for r in self.assets_for_run(to_id)}
        return {
            "new": [r for aid, r in new.items() if aid not in old],
            "resolved": [r for aid, r in old.items() if aid not in new],
            "persisting": [r for aid, r in new.items() if aid in old],
        }

    def run_history(self) -> list[dict]:
        """Per-run summary for trend lines: total assets, vulnerable count."""
        rows = self._con.execute(
            """
            SELECT r.id, r.started_at, r.label,
                   COUNT(a.asset_id) AS total,
                   COALESCE(SUM(a.quantum_vulnerable), 0) AS vulnerable
            FROM runs r LEFT JOIN assets a ON a.run_id = r.id
            GROUP BY r.id ORDER BY r.id
            """).fetchall()
        return [dict(r) for r in rows]
