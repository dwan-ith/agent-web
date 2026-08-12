"""Create a deterministic, secret-screened external review archive."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import zipfile

from release_evidence import EVIDENCE_FILES


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
SECRET_SUFFIXES = {
    ".jks",
    ".jwk",
    ".key",
    ".keystore",
    ".p8",
    ".p12",
    ".pem",
    ".pfx",
    ".token",
}
SECRET_NAMES = {
    ".envrc",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "kubeconfig",
    "netrc",
    "secret.json",
    "secrets.json",
}
PRIVATE_KEY_MARKERS = (
    b"-----BEGIN " + b"PRIVATE KEY-----",
    b"-----BEGIN RSA " + b"PRIVATE KEY-----",
    b"-----BEGIN EC " + b"PRIVATE KEY-----",
    b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----",
)


def review_files(root: Path) -> list[Path]:
    root = root.resolve(strict=True)
    files: list[Path] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if any(part in EXCLUDED_PARTS or part.endswith(".egg-info") for part in relative.parts):
            continue
        if relative.parts[0] not in INCLUDED_ROOTS and relative.as_posix() not in (
            INCLUDED_TOP_LEVEL
        ):
            continue
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root) or path.is_symlink():
            raise ValueError(f"refusing to package linked path: {relative}")
        if not path.is_file():
            continue
        lowered = path.name.casefold()
        if (
            lowered == ".env"
            or lowered.startswith(".env.")
            or lowered in SECRET_NAMES
            or path.suffix.casefold() in SECRET_SUFFIXES
        ):
            raise ValueError(f"refusing to package possible secret: {relative}")
        files.append(path)
    return sorted(files, key=lambda value: value.relative_to(root).as_posix())


def _release_files(
    release_evidence: Path,
    wheel_dir: Path,
    requirements_evidence: Path | None,
) -> list[tuple[str, bytes]]:
    evidence = release_evidence.resolve(strict=True)
    wheels = wheel_dir.resolve(strict=True)
    expected_evidence = {*EVIDENCE_FILES, "evidence-manifest.json"}
    actual_evidence = {path.name for path in evidence.iterdir() if path.is_file()}
    if actual_evidence != expected_evidence:
        raise ValueError("release-evidence directory is incomplete or contains surprises")
    evidence_manifest = json.loads(
        (evidence / "evidence-manifest.json").read_text(encoding="utf-8")
    )
    wheel_manifest = json.loads((wheels / "manifest.json").read_text(encoding="utf-8"))
    wheel_names = set(wheel_manifest.get("files", {}))
    actual_wheels = {path.name for path in wheels.glob("*.whl")}
    if not wheel_names or wheel_names != actual_wheels:
        raise ValueError("wheel directory does not match its manifest")
    expected_subjects = [
        {"name": name, "digest": {"sha256": wheel_manifest["files"][name]["sha256"]}}
        for name in sorted(wheel_names)
    ]
    if evidence_manifest.get("wheelSet") != expected_subjects:
        raise ValueError("release evidence and supplied wheels do not match")
    if not evidence.name.startswith("release-evidence-"):
        raise ValueError("release evidence directory must use a versioned canonical name")
    if not wheels.name.startswith("wheels-"):
        raise ValueError("wheel directory must use a versioned canonical name")
    files = [
        (f"artifacts/{evidence.name}/{name}", (evidence / name).read_bytes())
        for name in sorted(expected_evidence)
    ]
    files.append(
        (f"artifacts/{wheels.name}/manifest.json", (wheels / "manifest.json").read_bytes())
    )
    for name in sorted(wheel_names):
        path = wheels / name
        record = wheel_manifest["files"][name]
        content = path.read_bytes()
        if len(content) != record.get("bytes") or sha256(content).hexdigest() != record.get("sha256"):
            raise ValueError(f"wheel does not match its manifest: {name}")
        files.append((f"artifacts/{wheels.name}/{name}", content))
    if requirements_evidence is not None:
        requirement_path = requirements_evidence.resolve(strict=True)
        requirement_document = json.loads(requirement_path.read_text(encoding="utf-8"))
        if requirement_document.get("schema") != "agent-web-requirements-lock-evidence/1":
            raise ValueError("unsupported requirements-lock evidence")
        lock_digest = sha256((ROOT / "deploy/requirements.lock").read_bytes()).hexdigest()
        if requirement_document.get("lock", {}).get("sha256") != lock_digest:
            raise ValueError("requirements evidence does not match the packaged lock")
        if len(requirement_document.get("artifacts", {})) != 51:
            raise ValueError("requirements evidence does not cover the complete lock")
        files.append((f"artifacts/{requirement_path.name}", requirement_path.read_bytes()))
    return files


def build_bundle(
    root: Path,
    output: Path,
    *,
    release_evidence: Path | None = None,
    wheel_dir: Path | None = None,
    requirements_evidence: Path | None = None,
) -> dict[str, object]:
    root = root.resolve(strict=True)
    output = output.resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite review bundle: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    if (release_evidence is None) != (wheel_dir is None):
        raise ValueError("release evidence and wheel directory must be supplied together")
    if requirements_evidence is not None and release_evidence is None:
        raise ValueError("requirements evidence requires release evidence and wheels")
    records = []
    contents: list[tuple[str, bytes]] = []
    for path in review_files(root):
        relative = path.relative_to(root).as_posix()
        content = path.read_bytes()
        if any(marker in content for marker in PRIVATE_KEY_MARKERS):
            raise ValueError(
                f"refusing to package file containing private-key material: {relative}"
            )
        records.append(
            {"path": relative, "bytes": len(content), "sha256": sha256(content).hexdigest()}
        )
        contents.append((relative, content))
    if release_evidence is not None and wheel_dir is not None:
        for relative, content in _release_files(
            release_evidence, wheel_dir, requirements_evidence
        ):
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
        "secretScreen": (
            "sensitive filenames, linked paths, and private-key markers"
        ),
        "claims": {
            "externalReviewPerformed": False,
            "publicDeploymentVerified": False,
            "managedKeyCustodyVerified": False,
            "releaseEvidenceIncluded": release_evidence is not None,
            "wheelsIncluded": wheel_dir is not None,
            "requirementsLockEvidenceIncluded": requirements_evidence is not None,
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
    parser.add_argument("--release-evidence")
    parser.add_argument("--wheel-dir")
    parser.add_argument("--requirements-evidence")
    args = parser.parse_args()
    print(
        json.dumps(
            build_bundle(
                ROOT,
                Path(args.output),
                release_evidence=(Path(args.release_evidence) if args.release_evidence else None),
                wheel_dir=(Path(args.wheel_dir) if args.wheel_dir else None),
                requirements_evidence=(
                    Path(args.requirements_evidence)
                    if args.requirements_evidence else None
                ),
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
