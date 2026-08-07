"""Create a deterministic, secret-screened external review archive."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parents[1]
INCLUDED_ROOTS = {
    "acceptance",
    "agent-web-browser",
    "agent-web-server",
    "deploy",
    "docs",
    "libagentweb",
    "line-mode-agent-browser",
    "scripts",
    "sites",
    "skills",
}
INCLUDED_TOP_LEVEL = {"README.md", "SECURITY.md"}
EXCLUDED_PARTS = {
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
    "build",
    "dist",
    "artifacts",
}
SECRET_SUFFIXES = {".pem", ".key", ".token", ".p12", ".pfx"}


def review_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in EXCLUDED_PARTS or part.endswith(".egg-info") for part in relative.parts):
            continue
        if relative.parts[0] not in INCLUDED_ROOTS and relative.as_posix() not in (
            INCLUDED_TOP_LEVEL
        ):
            continue
        lowered = path.name.casefold()
        if lowered == ".env" or path.suffix.casefold() in SECRET_SUFFIXES:
            raise ValueError(f"refusing to package possible secret: {relative}")
        files.append(path)
    return sorted(files, key=lambda value: value.relative_to(root).as_posix())


def build_bundle(root: Path, output: Path) -> dict[str, object]:
    root = root.resolve(strict=True)
    output = output.resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite review bundle: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    records = []
    contents: list[tuple[str, bytes]] = []
    for path in review_files(root):
        relative = path.relative_to(root).as_posix()
        content = path.read_bytes()
        records.append(
            {"path": relative, "bytes": len(content), "sha256": sha256(content).hexdigest()}
        )
        contents.append((relative, content))
    manifest = {
        "schema": "agent-web-external-review-bundle/1",
        "files": records,
        "verificationCommands": [
            "python scripts/verify.py",
            "python scripts/public_beta_gate.py --manifest PUBLIC.json --output EVIDENCE.json",
            "python scripts/verify_vault_signer.py --help",
        ],
        "claims": {
            "externalReviewPerformed": False,
            "publicDeploymentVerified": False,
            "managedKeyCustodyVerified": False,
        },
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    with zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for relative, content in contents + [
            ("review-manifest.json", manifest_bytes)
        ]:
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    bundle_digest = sha256(output.read_bytes()).hexdigest()
    return {
        "status": "created",
        "bundle": str(output),
        "files": len(records),
        "sha256": bundle_digest,
        "externalReviewPerformed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            build_bundle(ROOT, Path(args.output)),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
