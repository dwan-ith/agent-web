"""Verify downloaded runtime wheels against the deployment hash lock."""

from __future__ import annotations

import argparse
from email.parser import BytesParser
from hashlib import sha256
import json
from pathlib import Path
import re
import zipfile


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATTERN = re.compile(
    r"([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s]+) "
    r"--hash=sha256:([0-9a-f]{64})\s+#\s+([A-Za-z0-9_.+-]+\.whl)"
)


def _normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def verify_wheelhouse(lock_path: Path, wheelhouse: Path) -> dict[str, object]:
    lock_path = lock_path.resolve(strict=True)
    wheelhouse = wheelhouse.resolve(strict=True)
    records: dict[str, dict[str, str | int]] = {}
    for raw in lock_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = LOCK_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(f"invalid hash-lock entry: {line}")
        name, version, expected_digest, filename = match.groups()
        path = wheelhouse / filename
        if not path.is_file():
            raise ValueError(f"wheelhouse is missing {filename}")
        content = path.read_bytes()
        actual_digest = sha256(content).hexdigest()
        if actual_digest != expected_digest:
            raise ValueError(f"wheel hash differs from lock: {filename}")
        with zipfile.ZipFile(path) as archive:
            metadata_names = [
                member
                for member in archive.namelist()
                if member.endswith(".dist-info/METADATA")
            ]
            if len(metadata_names) != 1:
                raise ValueError(f"wheel metadata layout is invalid: {filename}")
            metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
        if _normalized(metadata.get("Name", "")) != _normalized(name):
            raise ValueError(f"wheel project name differs from lock: {filename}")
        if metadata.get("Version") != version:
            raise ValueError(f"wheel version differs from lock: {filename}")
        records[filename] = {
            "project": name,
            "version": version,
            "bytes": len(content),
            "sha256": actual_digest,
        }
    actual_files = {path.name for path in wheelhouse.glob("*.whl")}
    if actual_files != set(records):
        raise ValueError("wheelhouse contains files not represented by the lock")
    return {
        "schema": "agent-web-requirements-lock-evidence/1",
        "target": {
            "python": "CPython 3.13",
            "os": "linux",
            "architecture": "x86_64",
        },
        "lock": {
            "path": "deploy/requirements.lock",
            "sha256": sha256(lock_path.read_bytes()).hexdigest(),
        },
        "artifacts": dict(sorted(records.items())),
        "claims": {
            "allLockedArtifactsPresent": True,
            "allArtifactHashesMatch": True,
            "allWheelNamesAndVersionsMatch": True,
            "packageIndexOriginAttested": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheelhouse", required=True)
    parser.add_argument("--lock", default=str(ROOT / "deploy/requirements.lock"))
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    if output.exists():
        raise FileExistsError(f"refusing to overwrite lock evidence: {output}")
    evidence = verify_wheelhouse(Path(args.lock), Path(args.wheelhouse))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "status": "passed",
                "artifacts": len(evidence["artifacts"]),
                "output": str(output),
                "packageIndexOriginAttested": False,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
