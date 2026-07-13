from cryptomap.model import AssetType, CryptoAsset, Exposure, canonical_family
from cryptomap.store import Store


def make_asset(**kw) -> CryptoAsset:
    defaults = dict(name="leaf cert", asset_type=AssetType.CERTIFICATE,
                    algorithm="rsa", location="certs/server.pem",
                    scanner="certs", key_size=2048)
    defaults.update(kw)
    return CryptoAsset(**defaults)


def test_family_normalization_and_vulnerability():
    assert canonical_family("prime256v1") == "EC"
    assert make_asset(algorithm="ed25519").quantum_vulnerable  # ECC is Shor-broken
    assert make_asset(algorithm="kyber").pqc_ready
    assert not make_asset(algorithm="AES", key_size=256).quantum_vulnerable


def test_asset_id_stable_across_metadata_changes():
    a = make_asset(details={"serial": 1})
    b = make_asset(details={"serial": 2}, data_lifespan_years=3)
    assert a.asset_id == b.asset_id
    assert a.asset_id != make_asset(location="other.pem").asset_id


def test_store_round_trip(tmp_path):
    store = Store(tmp_path / "t.db")
    assets = [make_asset(), make_asset(algorithm="ml-kem", name="pqc key",
                                       asset_type=AssetType.KEY_MATERIAL)]
    scores = {a.asset_id: (5.0, "medium") for a in assets}
    run_id = store.save_run(assets, scores, label="unit")
    assert store.latest_run_id() == run_id
    rows = store.assets_for_run(run_id)
    assert len(rows) == 2
    assert {r["algorithm"] for r in rows} == {"RSA", "ML-KEM"}
    hist = store.run_history()
    assert hist[-1]["total"] == 2 and hist[-1]["vulnerable"] == 1
