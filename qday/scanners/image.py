"""Container image scanner: inventory crypto inside docker-save / OCI tars.

Reads the archive (and every layer tarball inside it) in memory, so nothing is
extracted to disk. Certificates, keys, PKCS#12 keystores, and SSH key lines
found in any layer are reported with `layer!member` locations.
"""

from __future__ import annotations

import tarfile
from pathlib import Path, PurePosixPath
from typing import Iterator

from ..model import AssetType, CryptoAsset
from .certs import (
    _key_asset,
    _load_certs,
    build_cert_asset,
    pkcs12_assets_from_bytes,
    ssh_file_assets,
)

_MAX_MEMBER_BYTES = 1_000_000
_CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".key", ".pub", ".p8"}
_P12_EXTENSIONS = {".p12", ".pfx"}
_SSH_FILE_NAMES = {"authorized_keys", "known_hosts"}

_LAYER_SUFFIXES = (".tar.gz", ".tgz", ".tar")


def _member_suffix(name: str) -> str:
    return PurePosixPath(name).suffix.lower()


def _clean(name: str) -> str:
    normalized = str(PurePosixPath(name))
    return normalized.lstrip("./") or normalized


class ImageScanner:
    name = "image"

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def scan(self) -> Iterator[CryptoAsset]:
        with tarfile.open(self.path, mode="r:*") as outer:
            for member in outer:
                if not member.isfile():
                    continue
                name = _clean(member.name)
                if name.endswith(_LAYER_SUFFIXES):
                    fh = outer.extractfile(member)
                    if fh is None:
                        continue
                    with tarfile.open(fileobj=fh, mode="r:*") as layer:
                        for inner in layer:
                            if not inner.isfile():
                                continue
                            yield from self._scan_member(
                                f"{name}!{_clean(inner.name)}",
                                layer.extractfile(inner),
                            )
                else:
                    yield from self._scan_member(name, outer.extractfile(member))

    def _scan_member(self, location: str, fh) -> Iterator[CryptoAsset]:
        if fh is None:
            return
        member_name = PurePosixPath(location.rsplit("!", 1)[-1]).name
        suffix = _member_suffix(location.rsplit("!", 1)[-1])
        data = fh.read(_MAX_MEMBER_BYTES + 1)
        if len(data) > _MAX_MEMBER_BYTES:
            return
        try:
            if suffix in _P12_EXTENSIONS:
                for asset in pkcs12_assets_from_bytes(data, location):
                    asset.scanner = self.name
                    yield asset
                return
            if suffix in _CERT_EXTENSIONS:
                found = False
                for cert in _load_certs(data):
                    found = True
                    yield build_cert_asset(cert, location)
                if found:
                    return
                asset = _key_asset(data, location)
                if asset is not None:
                    asset.scanner = self.name
                    yield asset
                return
            if member_name in _SSH_FILE_NAMES:
                text = data.decode(errors="ignore")
                for asset in ssh_file_assets(text, location, member_name):
                    asset.scanner = self.name
                    yield asset
        except Exception as exc:
            yield CryptoAsset(
                name=f"unreadable image entry ({location})",
                asset_type=AssetType.KEY_MATERIAL,
                algorithm="UNKNOWN",
                location=location,
                scanner=self.name,
                details={"error": str(exc)},
            )
