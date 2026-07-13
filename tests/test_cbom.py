from cryptomap.cbom import export_cbom
from cryptomap.risk import score_asset
from cryptomap.scanners.certs import CertFileScanner
from cryptomap.store import Store


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
    assert props["cryptomap:quantum_vulnerable"] == "true"
    assert float(props["cryptomap:risk_score"]) > 0
