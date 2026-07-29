import json

from qday.cbom import export_cbom, import_cbom
from qday.cli import main
from qday.model import AssetType
from qday.risk import score_asset
from qday.scanners.certs import CertFileScanner
from qday.store import Store


def test_cbom_from_real_scan(cert_dir, tmp_path):
    assets = list(CertFileScanner(cert_dir).scan())
    scores = {a.asset_id: score_asset(a) for a in assets}
    store = Store(tmp_path / "t.db")
    run_id = store.save_run(assets, scores, label="cbom-test")

    doc = export_cbom(store.assets_for_run(run_id), store.run_info(run_id))

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert len(doc["components"]) == 2

    for comp in doc["components"]:
        assert comp["type"] == "cryptographic-asset"
        assert comp["bom-ref"]
        assert comp["cryptoProperties"]["assetType"] in {
            "certificate", "related-crypto-material", "protocol", "algorithm"}

    cert = next(c for c in doc["components"]
                if c["cryptoProperties"]["assetType"] == "certificate")
    assert cert["cryptoProperties"]["certificateProperties"]["issuerName"]
    props = {p["name"]: p["value"] for p in cert["properties"]}
    assert props["qday:quantum_vulnerable"] == "true"
    assert float(props["qday:risk_score"]) > 0

    # export -> import round-trips families, locations and annotations
    imported = import_cbom(doc)
    assert len(imported) == 2
    assert {a.algorithm for a in imported} == {a.algorithm for a in assets}
    assert {a.location for a in imported} == {a.location for a in assets}
    assert all(a.scanner == "import" for a in imported)


def test_import_foreign_cbom_and_cli(tmp_path, capsys):
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {"type": "cryptographic-asset", "name": "ML-DSA-65",
             "cryptoProperties": {"assetType": "algorithm"}},
            {"type": "cryptographic-asset", "name": "RSA-2048",
             "cryptoProperties": {
                 "assetType": "algorithm",
                 "algorithmProperties": {"parameterSetIdentifier": "2048"}},
             "evidence": {"occurrences": [{"location": "vault/hsm-1"}]}},
            {"type": "library", "name": "not-crypto"},
        ],
    }
    path = tmp_path / "foreign.json"
    path.write_text(json.dumps(doc))

    assets = import_cbom(doc)
    assert len(assets) == 2
    by_algo = {a.algorithm: a for a in assets}
    assert by_algo["ML-DSA"].pqc_ready
    assert by_algo["RSA"].key_size == 2048
    assert by_algo["RSA"].location == "vault/hsm-1"
    assert all(a.asset_type is AssetType.CODE_FINDING for a in assets)

    db = str(tmp_path / "d.db")
    assert main(["--db", db, "import", str(path)]) == 0
    assert "imported 2 crypto assets" in capsys.readouterr().out
    assert main(["--db", db, "report"]) == 0

    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert main(["--db", db, "import", str(bad)]) == 2
    assert main(["--db", db, "import", str(tmp_path / "missing.json")]) == 2
