import os

import pytest

from qday.agility import (
    AgileKey,
    CryptoPolicy,
    DeprecatedSuiteError,
    PolicyError,
)

CLASSICAL_SUITES = ["rsa-2048", "ecdsa-p256", "ecdsa-p384", "ed25519", "ed448"]


@pytest.mark.parametrize("suite", CLASSICAL_SUITES)
def test_sign_verify_round_trip(suite):
    policy = CryptoPolicy({"sign-thing": suite})
    priv, pub = policy.generate("sign-thing")
    data = b"attest this build"
    sig = policy.sign(priv, data)
    assert policy.verify(pub, data, sig)
    assert not policy.verify(pub, b"tampered", sig)


@pytest.mark.parametrize("suite", CLASSICAL_SUITES)
def test_key_envelope_round_trip(suite):
    policy = CryptoPolicy({"p": suite})
    priv, pub = policy.generate("p")
    data = b"payload"
    sig = policy.sign(priv, data)

    # Serialize both keys, reload without stating the algorithm, still verifies
    reloaded_priv = policy.load_key(policy.serialize_key(priv))
    reloaded_pub = policy.load_key(policy.serialize_key(pub))
    assert AgileKey.peek_suite(policy.serialize_key(pub)) == suite
    sig2 = policy.sign(reloaded_priv, data)
    assert policy.verify(reloaded_pub, data, sig2)


def test_to_file_round_trip_and_private_perms(tmp_path):
    policy = CryptoPolicy({"p": "ed25519"})
    priv, pub = policy.generate("p")
    provider = policy._provider_for("ed25519")
    priv_path, pub_path = tmp_path / "k.priv", tmp_path / "k.pub"
    priv.to_file(priv_path, provider)
    pub.to_file(pub_path, provider)

    data = b"payload"
    sig = policy.sign(policy.load_key(priv_path.read_bytes()), data)
    assert policy.verify(policy.load_key(pub_path.read_bytes()), data, sig)
    if os.name == "posix":
        assert priv_path.stat().st_mode & 0o777 == 0o600


def test_the_migration_is_config_only(tmp_path):
    """The whole promise: identical calling code, swap the binding, new keys
    use the new algorithm and old keys still verify."""

    def app_signs(policy, data):          # <- application code, never changes
        priv, pub = policy.generate("firmware-signing")
        return pub, policy.sign(priv, data)

    data = b"firmware v1.2.3"

    classical = CryptoPolicy({"firmware-signing": "ed25519"})
    pub_old, sig_old = app_signs(classical, data)
    assert pub_old.suite == "ed25519"

    # One-line policy change — same app_signs function
    migrated = CryptoPolicy({"firmware-signing": "hybrid:ed25519+ed448"})
    pub_new, sig_new = app_signs(migrated, data)
    assert pub_new.suite == "hybrid:ed25519+ed448"

    assert classical.verify(pub_old, data, sig_old)
    assert migrated.verify(pub_new, data, sig_new)


def test_hybrid_requires_both_arms():
    policy = CryptoPolicy({"p": "hybrid:ed25519+ed448"})
    priv, pub = policy.generate("p")
    data = b"dual-signed"
    sig = policy.sign(priv, data)
    assert policy.verify(pub, data, sig)

    # Corrupt only the second arm's bytes; combined verify must fail
    corrupt = bytearray(sig)
    corrupt[-1] ^= 0xFF
    assert not policy.verify(pub, data, bytes(corrupt))


def test_deprecated_suite_blocks_new_keys():
    policy = CryptoPolicy({"legacy": "rsa-2048"}, deprecated=["rsa-2048"])
    with pytest.raises(DeprecatedSuiteError):
        policy.generate("legacy")


def test_unknown_purpose_and_suite():
    policy = CryptoPolicy({"p": "ed25519"})
    with pytest.raises(PolicyError):
        policy.generate("nope")
    with pytest.raises(PolicyError):
        CryptoPolicy({"p": "quantum-magic-9000"})


def test_from_file_and_inventory(tmp_path):
    cfg = tmp_path / "agility.toml"
    cfg.write_text("""
[agility.purposes]
document-signing = "rsa-3072"
token-signing    = "ed25519"
firmware-signing = "hybrid:ed25519+ml-dsa-65"

[agility.policy]
deprecated = ["rsa-2048"]
""")
    policy = CryptoPolicy.from_file(cfg)
    inv = {row["purpose"]: row for row in policy.inventory()}

    assert inv["document-signing"]["family"] == "RSA"
    assert inv["document-signing"]["quantum_safe"] is False
    assert inv["token-signing"]["suite"] == "ed25519"
    # hybrid with a PQC arm counts as quantum-safe
    assert inv["firmware-signing"]["quantum_safe"] is True


def test_agility_scanner_inventories_policy(tmp_path):
    from qday.scanners.agility import AgilityScanner

    cfg = tmp_path / "agility.toml"
    cfg.write_text("""
[agility.purposes]
document-signing = "rsa-2048"
firmware-signing = "hybrid:ed25519+ml-dsa-65"

[agility.policy]
deprecated = ["rsa-2048"]
""")
    assets = {a.details["purpose"]: a for a in AgilityScanner(cfg).scan()}

    doc = assets["document-signing"]
    assert doc.algorithm == "RSA" and doc.quantum_vulnerable
    assert doc.details["deprecated"] is True

    fw = assets["firmware-signing"]
    assert fw.pqc_ready and not fw.quantum_vulnerable  # PQC hybrid is safe


def test_mlkem_wired_but_backend_optional():
    from qday.agility.providers import BackendUnavailable, MLKEMProvider

    policy = CryptoPolicy({"session-keys": "ml-kem-768"})
    (row,) = policy.inventory()
    assert row["family"] == "ML-KEM" and row["quantum_safe"] is True

    try:
        import oqs  # noqa: F401
    except ImportError:
        with pytest.raises(BackendUnavailable):
            MLKEMProvider("ml-kem-768").generate()
    else:
        priv, pub = policy.generate("session-keys")
        ciphertext, secret = policy.encapsulate(pub)
        assert policy.decapsulate(priv, ciphertext) == secret


def test_sign_and_kem_apis_do_not_cross():
    policy = CryptoPolicy({"session-keys": "ml-kem-768", "sig": "ed25519"})
    priv, pub = policy.generate("sig")
    with pytest.raises(PolicyError):
        policy.encapsulate(pub)
    with pytest.raises(PolicyError):
        policy.decapsulate(priv, b"ct")
    with pytest.raises(PolicyError):
        policy.sign(AgileKey("ml-kem-768", True, None), b"x")


def test_hybrid_rejects_kem_arm():
    with pytest.raises(PolicyError):
        CryptoPolicy({"p": "hybrid:ed25519+ml-kem-768"})


def test_mldsa_wired_but_backend_optional():
    """The PQC suite constructs and reports correctly even without liboqs;
    only actual key ops require the backend."""
    from qday.agility.providers import BackendUnavailable, MLDSAProvider

    policy = CryptoPolicy({"pq": "ml-dsa-65"})
    (row,) = policy.inventory()
    assert row["family"] == "ML-DSA" and row["quantum_safe"] is True

    provider = MLDSAProvider("ml-dsa-65")
    try:
        import oqs  # noqa: F401
    except ImportError:
        with pytest.raises(BackendUnavailable):
            provider.generate()
