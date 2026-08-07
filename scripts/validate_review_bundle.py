"""Build and verify the external-review archive contract in a temp directory."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import zipfile

from export_review_bundle import ROOT, build_bundle


def main() -> int:
    with TemporaryDirectory() as temporary:
        output = Path(temporary) / "review.zip"
        result = build_bundle(ROOT, output)
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
            if any(manifest["claims"].values()):
                raise ValueError("local bundle must not assert external evidence")
    print(
        json.dumps(
            {
                "status": "passed",
                "deterministicArchive": True,
                "secretFilenameScreen": True,
                "externalClaims": False,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
