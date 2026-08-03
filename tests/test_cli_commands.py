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


def test_prune_keep(tmp_path, capsys):
    db = str(tmp_path / "t.db")
    ids = [seed_run(db) for _ in range(3)]
    assert main(["--db", db, "prune", "--keep", "1", "--dry-run"]) == 0
    assert "would delete 2" in capsys.readouterr().out
    assert len(Store(db).run_history()) == 3
    assert main(["--db", db, "prune", "--keep", "1"]) == 0
    history = Store(db).run_history()
    assert [h["id"] for h in history] == [ids[-1]]
    assert Store(db).assets_for_run(ids[0]) == []


def test_prune_older_than_and_nothing(tmp_path, capsys):
    db = str(tmp_path / "t.db")
    seed_run(db)
    assert main(["--db", db, "prune", "--older-than", "30"]) == 0
    assert "nothing to prune" in capsys.readouterr().out
    assert main(["--db", db, "prune", "--older-than", "0"]) == 0
    assert Store(db).run_history() == []


def test_waivers_status_and_hits(tmp_path, capsys):
    db = str(tmp_path / "t.db")
    seed_run(db)
    cfg = tmp_path / "qday.toml"
    cfg.write_text(
        '[[waive]]\nmatch = "certs/*"\nreason = "migrating"\n'
        'until = 2099-01-01\n'
        '[[waive]]\nmatch = "other/*"\nreason = "gone"\nuntil = 2020-01-01\n')
    assert main(["--db", db, "waivers", "--config", str(cfg)]) == 0
    out = capsys.readouterr().out
    active = next(line for line in out.splitlines() if "certs/*" in line)
    expired = next(line for line in out.splitlines() if "other/*" in line)
    assert active.split()[:1] + active.split()[3:4] == ["ACTIVE", "2"]
    assert expired.split()[:1] + expired.split()[3:4] == ["EXPIRED", "0"]


def test_waivers_none_defined(tmp_path, capsys):
    cfg = tmp_path / "qday.toml"
    cfg.write_text("[scan]\n")
    db = str(tmp_path / "t.db")
    assert main(["--db", db, "waivers", "--config", str(cfg)]) == 0
    assert "no waivers defined" in capsys.readouterr().out


def test_scan_fail_under(tmp_path, cert_dir, capsys):
    db = str(tmp_path / "t.db")
    args = ["--db", db, "scan", "--certs", str(cert_dir)]
    assert main(args + ["--fail-under", "50"]) == 3
    assert "fail-under=50" in capsys.readouterr().err
    assert main(args + ["--fail-under", "0"]) == 0


def test_trend_bar_and_json(tmp_path, capsys):
    db = str(tmp_path / "t.db")
    seed_run(db)
    seed_run(db, assets=[make_asset(algorithm="ml-kem")])
    assert main(["--db", db, "trend"]) == 0
    out = capsys.readouterr().out
    assert " 50.0% |" in out and "100.0% |" in out
    assert main(["--db", db, "trend", "--json"]) == 0
    points = json.loads(capsys.readouterr().out)
    assert [p["safe_pct"] for p in points] == [50.0, 100.0]
