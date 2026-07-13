"""Scanner interface: anything that yields CryptoAssets."""

from __future__ import annotations

from typing import Iterator, Protocol

from ..model import CryptoAsset


class Scanner(Protocol):
    name: str

    def scan(self) -> Iterator[CryptoAsset]: ...
