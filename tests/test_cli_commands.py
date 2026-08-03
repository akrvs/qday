"""CLI subcommand tests driven through main(argv) against a temp db."""

import json

from qday.cli import main
from qday.model import AssetType, CryptoAsset
from qday.store import Store


def make_asset(**kw) -> CryptoAsset:
    defaults = dict(name="leaf cert", asset_type=AssetType.CERTIFICATE,
                    algorithm="rsa", location="certs/server.pem",
                    scanner="certs", key_size=2048)
    defaults.update(kw)
    return CryptoAsset(**defaults)


def seed_run(db, assets=None, label=None) -> int:
    assets = assets if assets is not None else [
        make_asset(),
        make_asset(algorithm="ml-kem", name="pqc key",
                   asset_type=AssetType.KEY_MATERIAL),
    ]
    scores = {a.asset_id: (5.0, "medium") for a in assets}
    return Store(db).save_run(assets, scores, label=label)


def test_runs_lists_history(tmp_path, capsys):
    db = str(tmp_path / "t.db")
    seed_run(db, label="first")
    assert main(["--db", db, "runs"]) == 0
    out = capsys.readouterr().out
    assert "first" in out and "50.0" in out


def test_runs_json(tmp_path, capsys):
    db = str(tmp_path / "t.db")
    seed_run(db)
    assert main(["--db", db, "runs", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["total"] == 2 and rows[0]["safe_pct"] == 50.0


def test_runs_empty_db(tmp_path):
    assert main(["--db", str(tmp_path / "t.db"), "runs"]) == 1
