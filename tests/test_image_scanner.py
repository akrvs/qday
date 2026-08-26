"""Image scanner: crypto inside docker-save style archives, nothing on disk."""

import io
import tarfile

from qday.cli import main
from qday.scanners.image import ImageScanner


def _make_image(tmp_path):
    """A docker-save style tar with one layer holding a cert and a key line."""
    from tests.conftest import make_self_signed
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = make_self_signed(key, "image.test")
    pem = cert.public_bytes(serialization.Encoding.PEM)

    layer_buf = io.BytesIO()
    with tarfile.open(fileobj=layer_buf, mode="w") as layer:
        entry = tarfile.TarInfo("etc/ssl/certs/server.pem")
        entry.size = len(pem)
        layer.addfile(entry, io.BytesIO(pem))
    layer_bytes = layer_buf.getvalue()

    outer_path = tmp_path / "image.tar"
    with tarfile.open(outer_path, "w") as outer:
        entry = tarfile.TarInfo("blobs/sha256/layer.tar")
        entry.size = len(layer_bytes)
        outer.addfile(entry, io.BytesIO(layer_bytes))
    return outer_path


def test_image_scanner_finds_cert_inside_layer(tmp_path):
    path = _make_image(tmp_path)
    assets = list(ImageScanner(path).scan())
    certs = [a for a in assets if a.asset_type.value == "certificate"]
    assert len(certs) == 1
    assert "layer.tar!etc/ssl/certs/server.pem" in certs[0].location
    assert certs[0].algorithm == "RSA"


def test_scan_command_accepts_image_flag(tmp_path, capsys):
    path = _make_image(tmp_path)
    db = str(tmp_path / "t.db")
    assert main(["--db", db, "scan", "--image", str(path)]) == 0
    out = capsys.readouterr().out
    assert "1 crypto assets found" in out


def test_scan_command_rejects_bad_archive(tmp_path, capsys):
    bad = tmp_path / "bad.tar"
    bad.write_bytes(b"definitely not a tar")
    db = str(tmp_path / "t.db")
    assert main(["--db", db, "scan", "--image", str(bad)]) == 2
    assert "image error" in capsys.readouterr().err
