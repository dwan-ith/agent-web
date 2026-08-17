"""Build and verify the external-review archive contract in a temp directory."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import zipfile

from export_review_bundle import ROOT, build_bundle, review_files
from release_evidence import generate_release_evidence


WHEELS = ROOT / "artifacts/wheels-20260813-registry-federation"
REQUIREMENTS_EVIDENCE = ROOT / "artifacts/requirements-lock-evidence-20260813.json"


def main() -> int:
    with TemporaryDirectory() as temporary:
        temporary_path = Path(temporary)
        screening_root = temporary_path / "screening"
        (screening_root / "scripts").mkdir(parents=True)
        environment_secret = screening_root / "scripts" / ".env.production"
        environment_secret.write_text("TOKEN=must-not-leak\n", encoding="utf-8")
        try:
            review_files(screening_root)
        except ValueError as exc:
            if ".env.production" not in str(exc):
                raise
        else:
            raise ValueError("review bundle accepted a variant environment file")

        private_key_root = temporary_path / "private-key-screening"
        (private_key_root / "scripts").mkdir(parents=True)
        (private_key_root / "scripts" / "settings.txt").write_bytes(
            b"-----BEGIN " + b"PRIVATE KEY-----\nnot-a-real-key\n"
        )
        try:
            build_bundle(private_key_root, temporary_path / "unsafe-review.zip")
        except ValueError as exc:
            if "private-key material" not in str(exc):
                raise
        else:
            raise ValueError("review bundle accepted embedded private-key material")

        evidence = temporary_path / "release-evidence-20260812"
        generate_release_evidence(WHEELS, evidence)
        output = temporary_path / "review.zip"
        result = build_bundle(
            ROOT,
            output,
            release_evidence=evidence,
            wheel_dir=WHEELS,
            requirements_evidence=REQUIREMENTS_EVIDENCE,
        )
        if result["sha256"] != sha256(output.read_bytes()).hexdigest():
            raise ValueError("review bundle digest is incorrect")
        with zipfile.ZipFile(output) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ValueError("review bundle contains duplicate paths")
            manifest = json.loads(archive.read("review-manifest.json"))
            for record in manifest["files"]:
                content = archive.read(record["path"])
                if len(content) != record["bytes"]:
                    raise ValueError("review file size does not match manifest")
                if sha256(content).hexdigest() != record["sha256"]:
                    raise ValueError("review file digest does not match manifest")
            external_claims = {
                key: value
                for key, value in manifest["claims"].items()
                if key not in {
                    "releaseEvidenceIncluded",
                    "wheelsIncluded",
                    "requirementsLockEvidenceIncluded",
                }
            }
            if any(external_claims.values()):
                raise ValueError("local bundle must not assert external evidence")
            if manifest["claims"].get("releaseEvidenceIncluded") is not True:
                raise ValueError("review bundle omitted release evidence")
            if manifest["claims"].get("wheelsIncluded") is not True:
                raise ValueError("review bundle omitted release wheels")
            if manifest["claims"].get("requirementsLockEvidenceIncluded") is not True:
                raise ValueError("review bundle omitted requirements-lock evidence")
    print(
        json.dumps(
            {
                "status": "passed",
                "deterministicArchive": True,
                "secretPathScreen": True,
                "externalClaims": False,
                "releaseEvidenceIncluded": True,
                "wheelsIncluded": True,
                "requirementsLockEvidenceIncluded": True,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
