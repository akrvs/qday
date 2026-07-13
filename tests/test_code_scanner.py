import textwrap

import pytest

from qday.scanners.code import CodeScanner, load_rules


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "app.py").write_text(textwrap.dedent("""\
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
    """))
    (tmp_path / "Signer.java").write_text(
        'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n'
        'kpg.initialize(4096);\n')
    (tmp_path / "main.go").write_text(
        'priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)\n')
    (tmp_path / "deploy.sh").write_text(
        "openssl genrsa -out server.key 1024\n")
    (tmp_path / "oops.txt").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n")
    (tmp_path / "clean.py").write_text("print('no crypto here')\n")
    node = tmp_path / "node_modules" / "dep"
    node.mkdir(parents=True)
    (node / "index.js").write_text("crypto.generateKeyPairSync('rsa', {})\n")
    return tmp_path


def test_rules_load():
    by_ext, generic = load_rules()
    assert ".py" in by_ext and ".java" in by_ext and ".go" in by_ext
    assert generic  # embedded-key rules


def test_code_scanner_findings(repo):
    assets = list(CodeScanner(repo).scan())
    by_rule = {a.details["rule"]: a for a in assets}

    assert by_rule["py-rsa-keygen"].key_size == 2048  # multi-line lookahead
    assert by_rule["java-keypairgen-rsa"].key_size == 4096
    assert by_rule["go-ecdsa-generate"].algorithm == "ECDSA"
    assert by_rule["generic-openssl-genrsa"].key_size == 1024
    assert "note" in by_rule["generic-embedded-rsa-key"].details

    locations = [a.location for a in assets]
    assert any(loc.startswith("app.py:") for loc in locations)
    assert not any("node_modules" in loc for loc in locations)
    assert not any(loc.startswith("clean.py") for loc in locations)
    assert all(a.quantum_vulnerable or a.algorithm == "UNKNOWN"
               for a in assets)
