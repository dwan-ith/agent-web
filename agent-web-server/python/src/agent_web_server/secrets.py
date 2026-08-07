"""Small, strict helpers for loading runtime secrets from mounted files."""

from __future__ import annotations

from pathlib import Path


def read_secret_file(path: str | Path, *, max_bytes: int = 4096) -> str:
    """Read one non-empty UTF-8 secret without accepting oversized files."""

    secret_path = Path(path)
    size = secret_path.stat().st_size
    if size < 1 or size > max_bytes:
        raise ValueError(
            f"secret file must contain between 1 and {max_bytes} bytes"
        )
    value = secret_path.read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError("secret file is empty")
    if "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError("secret file must contain exactly one text value")
    return value
