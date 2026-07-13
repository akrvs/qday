from qday.model import AssetType, CryptoAsset, Exposure
from qday.risk import score_asset


def asset(**kw):
    defaults = dict(name="a", asset_type=AssetType.CERTIFICATE,
                    algorithm="RSA", key_size=2048, location="x",
                    scanner="t")
    defaults.update(kw)
    return CryptoAsset(**defaults)


def test_public_long_lived_rsa_is_critical():
    score, level = score_asset(asset(exposure=Exposure.PUBLIC,
                                     data_lifespan_years=20))
    assert level == "critical" and score == 10.0


def test_short_lived_local_rsa_scores_lower_than_public():
    lo, _ = score_asset(asset(data_lifespan_years=1))
    hi, _ = score_asset(asset(exposure=Exposure.PUBLIC,
                              data_lifespan_years=20))
    assert lo < hi


def test_classically_weak_rsa_outranks_sound_rsa():
    weak, _ = score_asset(asset(key_size=1024))
    sound, _ = score_asset(asset(key_size=4096))
    assert weak > sound


def test_pqc_scores_zero():
    score, level = score_asset(asset(algorithm="ML-DSA",
                                     exposure=Exposure.PUBLIC))
    assert score == 0.0 and level == "none"


def test_aes256_safe_aes128_flagged():
    safe, _ = score_asset(asset(algorithm="AES", key_size=256))
    weak, weak_level = score_asset(asset(algorithm="AES", key_size=128))
    assert safe == 0.0 and weak > 0 and weak_level in {"low", "medium"}


def test_expired_cert_bump():
    fresh, _ = score_asset(asset())
    expired, _ = score_asset(asset(details={"expired": True}))
    assert expired > fresh
