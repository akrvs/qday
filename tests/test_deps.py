import json

import pytest

from qday.model import AssetType
from qday.scanners.deps import DepScanner, load_catalog


@pytest.fixture
def manifests(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# app deps\n"
        "Flask==3.0.0\n"
        "cryptography>=42.0\n"
        "pyjwt==2.8.0\n"
        "requests\n")
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app"},
            "node_modules/jsonwebtoken": {"version": "9.0.2"},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/elliptic": {"version": "6.5.4"},
        },
    }))
    (tmp_path / "go.mod").write_text(
        "module example.com/app\n\n"
        "go 1.22\n\n"
        "require (\n"
        "\tgolang.org/x/crypto v0.21.0\n"
        "\tgithub.com/gin-gonic/gin v1.9.1\n"
        ")\n")
    (tmp_path / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        "<dependencies>"
        "<dependency><groupId>org.bouncycastle</groupId>"
        "<artifactId>bcprov-jdk18on</artifactId>"
        "<version>1.77</version></dependency>"
        "<dependency><groupId>org.slf4j</groupId>"
        "<artifactId>slf4j-api</artifactId>"
        "<version>2.0.9</version></dependency>"
        "</dependencies></project>")
    node = tmp_path / "node_modules" / "sub"
    node.mkdir(parents=True)
    (node / "package-lock.json").write_text('{"packages":{}}')  # must skip
    return tmp_path


def test_catalog_shape():
    cat = load_catalog()
    assert "pypi" in cat and cat["pypi"]["cryptography"] == "EC"


def test_dep_scanner_across_ecosystems(manifests):
    assets = list(DepScanner(manifests).scan())
    found = {a.details["package"]: a for a in assets}

    # matched crypto libs, across four ecosystems
    assert "cryptography" in found and found["cryptography"].algorithm == "EC"
    assert found["pyjwt"].algorithm == "RSA"
    assert found["jsonwebtoken"].algorithm == "RSA"
    assert found["elliptic"].algorithm == "ECDSA"
    assert found["golang.org/x/crypto"].algorithm == "EC"      # go prefix
    assert "org.bouncycastle:bcprov-jdk18on" in found          # maven prefix

    # non-crypto deps ignored; every finding is DEPENDENCY type
    assert "flask" not in found and "lodash" not in found
    assert all(a.asset_type is AssetType.DEPENDENCY for a in assets)

    # version captured, and node_modules skipped
    assert found["jsonwebtoken"].details["version"] == "9.0.2"
    assert not any("node_modules" in a.location for a in assets)


def test_v2_lockfile_with_both_sections_not_duplicated(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 2,
        "packages": {"node_modules/elliptic": {"version": "6.5.4"}},
        "dependencies": {"elliptic": {"version": "6.5.4"}},
    }))
    assets = list(DepScanner(tmp_path).scan())
    assert [a.details["package"] for a in assets] == ["elliptic"]


def test_broken_manifest_is_skipped_not_fatal(tmp_path):
    (tmp_path / "package-lock.json").write_text("{ this is not json ")
    (tmp_path / "requirements.txt").write_text("cryptography==42.0\n")
    assets = list(DepScanner(tmp_path).scan())
    assert [a.details["package"] for a in assets] == ["cryptography"]
