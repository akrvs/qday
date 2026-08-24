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


def test_export_csv(tmp_path, capsys):
    import csv

    db = str(tmp_path / "t.db")
    seed_run(db)
    out_path = tmp_path / "report.csv"
    assert main(["--db", db, "export", "--csv", "-o", str(out_path)]) == 0
    rows = list(csv.DictReader(out_path.open(newline="")))
    assert len(rows) == 2
    rsa = next(r for r in rows if r["algorithm"] == "RSA")
    assert rsa["quantum_vulnerable"] == "1"
    assert "ML-DSA" in rsa["remediation"]


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


def test_export_markdown_for_ci(tmp_path, capsys):
    db = str(tmp_path / "t.db")
    seed_run(db, label="nightly")
    out_path = tmp_path / "comment.md"
    assert main(["--db", db, "export", "--md", "-o", str(out_path)]) == 0
    body = out_path.read_text(encoding="utf-8")
    assert "# QDAY PQC migration report" in body
    assert "nightly" in body and "50.0%" in body
    assert "| risk | score | algorithm |" in body


def test_tickets_jira_and_linear(tmp_path, capsys):
    db = str(tmp_path / "t.db")
    seed_run(db)
    assert main(["--db", db, "tickets", "--format", "jira"]) == 0
    jira = capsys.readouterr().out
    assert "h3. Migrate RSA-2048 certificate" in jira
    assert "||Field||Value||" in jira
    out_path = tmp_path / "tickets.md"
    assert main(["--db", db, "tickets", "--format", "linear",
                 "-o", str(out_path)]) == 0
    linear = out_path.read_text(encoding="utf-8")
    assert "### Migrate RSA-2048 certificate" in linear
    assert "- **Migrate to:** ML-DSA" in linear


def test_tickets_threshold_and_empty(tmp_path, capsys):
    db = str(tmp_path / "t.db")
    seed_run(db)
    assert main(["--db", db, "tickets", "--fail-on", "critical"]) == 0
    assert "nothing to file" in capsys.readouterr().out


def test_expired_waiver_hits_unit():
    import datetime as dt

    from qday.config import expired_waiver_hits
    today = dt.date.today()
    waivers = [
        {"match": "certs/*", "reason": "old", "until": today - dt.timedelta(days=1)},
        {"match": "*", "reason": "live", "until": today + dt.timedelta(days=1)},
    ]
    assets = [make_asset(), make_asset(location="other/x.pem")]
    hits = expired_waiver_hits(assets, waivers, today=today)
    assert len(hits) == 1 and hits[0][0]["match"] == "certs/*"
    assert hits[0][1] == 1


def test_scan_refuses_private_targets_without_authorization(tmp_path, capsys):
    db = str(tmp_path / "t.db")
    code = main(["--db", db, "scan", "--tls", "127.0.0.1:443",
                 "--ssh", "127.0.0.1:22"])
    assert code == 2
    err = capsys.readouterr().err
    assert "private-range target(s) found" in err
    assert "--i-own-this-network" in err


def test_scan_authorized_private_targets_run(tmp_path, capsys):
    db = str(tmp_path / "t.db")
    closed = 1  # port 1 on loopback refuses instantly; still a full scan cycle
    assert main(["--db", db, "scan", "--i-own-this-network",
                 "--tls", f"127.0.0.1:{closed}"]) == 0
    out = capsys.readouterr().out
    assert "internal scope authorized" in out
    assert "1 crypto assets found" in out


def test_scan_config_authorized_private(tmp_path, capsys):
    db = str(tmp_path / "t.db")
    cfg = tmp_path / "qday.toml"
    cfg.write_text('[scan]\ntls = ["127.0.0.1:1"]\nauthorized_private = true\n')
    assert main(["--db", db, "scan", "--config", str(cfg)]) == 0
    assert "internal scope authorized" in capsys.readouterr().out
