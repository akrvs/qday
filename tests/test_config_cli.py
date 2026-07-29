import pytest

from qday.cli import main
from qday.config import ConfigError, apply_annotations, load_config
from qday.model import AssetType, CryptoAsset, Exposure


def test_load_config_and_annotate(tmp_path):
    cfg_file = tmp_path / "qday.toml"
    cfg_file.write_text("""
[scan]
tls = ["db.internal:5432"]
code = ["src"]

[[annotate]]
match = "db.internal*"
lifespan_years = 25
exposure = "internal"

[[annotate]]
match = "*"
lifespan_years = 5
""")
    cfg = load_config(cfg_file)
    assert cfg["tls"] == ["db.internal:5432"] and cfg["code"] == ["src"]

    assets = [
        CryptoAsset(name="ep", asset_type=AssetType.TLS_ENDPOINT,
                    algorithm="ECDH", location="db.internal:5432",
                    scanner="tls"),
        CryptoAsset(name="f", asset_type=AssetType.CODE_FINDING,
                    algorithm="RSA", location="src/app.py:2", scanner="code"),
    ]
    assert apply_annotations(assets, cfg["annotations"]) == 2
    # first matching rule wins per field
    assert assets[0].data_lifespan_years == 25
    assert assets[0].exposure is Exposure.INTERNAL
    assert assets[1].data_lifespan_years == 5


def test_config_rejects_bad_exposure(tmp_path):
    bad = tmp_path / "qday.toml"
    bad.write_text('[[annotate]]\nmatch = "*"\nexposure = "cosmic"\n')
    with pytest.raises(ConfigError):
        load_config(bad)


def test_scan_diff_and_fail_on(cert_dir, tmp_path, capsys):
    db = str(tmp_path / "d.db")
    # run 1: certs present -> quantum-vulnerable -> fail-on trips
    rc = main(["--db", db, "scan", "--certs", str(cert_dir),
               "--fail-on", "high"])
    assert rc == 3

    # run 2: same dir minus the EC key -> that asset shows as resolved
    (cert_dir / "signer.key").unlink()
    assert main(["--db", db, "scan", "--certs", str(cert_dir)]) == 0

    capsys.readouterr()
    assert main(["--db", db, "diff"]) == 0
    out = capsys.readouterr().out
    assert "-1 resolved" in out and "signer.key" in out


def test_repeatable_dir_flags(cert_dir, tmp_path, capsys):
    other = tmp_path / "other"
    other.mkdir()
    (other / "extra.key").write_bytes((cert_dir / "signer.key").read_bytes())
    assert main(["--db", str(tmp_path / "d.db"), "scan",
                 "--certs", str(cert_dir), "--certs", str(other)]) == 0
    assert "4 crypto assets" in capsys.readouterr().out


def test_scan_rejects_bad_tls_target(tmp_path, capsys):
    db = str(tmp_path / "d.db")
    for target in ("host:notaport", ":443", "host:0", "host:70000"):
        assert main(["--db", db, "scan", "--tls", target]) == 2
    assert "invalid TLS target" in capsys.readouterr().err


def test_scan_uses_config_targets(cert_dir, tmp_path, capsys, monkeypatch):
    cfg = tmp_path / "qday.toml"
    cfg.write_text(f"""
[scan]
certs = ["{cert_dir.as_posix()}"]

[[annotate]]
match = "*"
lifespan_years = 30
""")
    monkeypatch.chdir(tmp_path)
    assert main(["--db", str(tmp_path / "d.db"), "scan"]) == 0
    out = capsys.readouterr().out
    assert "2 annotated via config" in out
