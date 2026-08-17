"""Create a deterministic digest manifest for an already-built wheel set."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel-dir", required=True)
    parser.add_argument("--created-at", required=True)
    args = parser.parse_args()
    wheel_dir = Path(args.wheel_dir).resolve(strict=True)
    manifest = {
        "schema": "agent-web-wheel-set/1",
        "createdAt": args.created_at,
        "files": {},
    }
    for path in sorted(wheel_dir.glob("*.whl")):
        content = path.read_bytes()
        manifest["files"][path.name] = {
            "bytes": len(content),
            "sha256": sha256(content).hexdigest(),
        }
    if not manifest["files"]:
        raise ValueError("wheel directory contains no wheels")
    output = wheel_dir / "manifest.json"
    if output.exists():
        raise FileExistsError(f"refusing to overwrite {output}")
    output.write_text(
        json.dumps(manifest, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
