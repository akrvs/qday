"""Shared scanner plumbing: a deterministic directory walk that prunes
skipped directories instead of descending into them and filtering after,
and skips unreadable or oversized files."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator


def walk_files(root: str | Path, skip_dirs: set[str],
               max_bytes: int) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip_dirs)
        for name in sorted(filenames):
            path = Path(dirpath, name)
            try:
                if path.stat().st_size <= max_bytes:
                    yield path
            except OSError:
                continue
