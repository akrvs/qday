import json

from qday.cli import main
from qday.model import AssetType, CryptoAsset
from qday.sarif import export_sarif
from qday.store import Store


def _rows(tmp_path):
    assets = [
        CryptoAsset(name="RSA.new(2048)", asset_type=AssetType.CODE_FINDING,
                    algorithm="RSA", location="src/app.py:42", scanner="code",
                    key_size=2048),
        CryptoAsset(name="TLS endpoint api:443",
                    asset_type=AssetType.TLS_ENDPOINT, algorithm="ECDH",
                    location="api.example.com:443", scanner="tls"),
        CryptoAsset(name="pqc key", asset_type=AssetType.KEY_MATERIAL,
                    algorithm="ml-kem", location="keys/enc.key",
                    scanner="certs"),
    ]
    scores = {assets[0].asset_id: (8.5, "critical"),
              assets[1].asset_id: (5.0, "medium"),
              assets[2].asset_id: (0.0, "none")}
    store = Store(tmp_path / "t.db")
    run_id = store.save_run(assets, scores)
    return store, run_id


def test_sarif_structure_and_levels(tmp_path):
    store, run_id = _rows(tmp_path)
    doc = export_sarif(store.assets_for_run(run_id))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "qday"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids == {"qday-RSA", "qday-ECDH", "qday-ML-KEM"}
    by_rule = {r["ruleId"]: r for r in run["results"]}
    assert by_rule["qday-RSA"]["level"] == "error"
    assert by_rule["qday-ECDH"]["level"] == "warning"
    assert by_rule["qday-ML-KEM"]["level"] == "note"

    code_loc = by_rule["qday-RSA"]["locations"][0]["physicalLocation"]
    assert code_loc["artifactLocation"]["uri"] == "src/app.py"
    assert code_loc["region"]["startLine"] == 42

    tls_loc = by_rule["qday-ECDH"]["locations"][0]["physicalLocation"]
    assert tls_loc["artifactLocation"]["uri"] == "api.example.com:443"
    assert "region" not in tls_loc
    assert "X25519MLKEM768" in by_rule["qday-ECDH"]["message"]["text"]


def test_export_sarif_cli(tmp_path, capsys):
    store, _ = _rows(tmp_path)
    out_path = tmp_path / "out.sarif"
    assert main(["--db", str(store.path), "export", "--sarif",
                 "-o", str(out_path)]) == 0
    doc = json.loads(out_path.read_text())
    assert doc["runs"][0]["results"]
