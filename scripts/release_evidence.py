"""Generate deterministic, honest supply-chain evidence for an Agent Web wheel set."""

from __future__ import annotations

from email.parser import BytesParser
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import quote
from uuid import NAMESPACE_URL, uuid5
import zipfile


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOTS = (
    "libagentweb/python",
    "agent-web-server/python",
    "sites/moltbook/python",
    "sites/forecast/python",
    "sites/registry/python",
    "sites/native-knowledge/python",
    "line-mode-agent-browser/python",
    "agent-web-browser/python",
)
EVIDENCE_FILES = (
    "agent-web.cdx.json",
    "agent-web.provenance.json",
    "release-claims.json",
)


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _normalized_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def _purl(name: str, version: str) -> str:
    return f"pkg:pypi/{quote(_normalized_name(name), safe='-')}@{quote(version, safe='.-')}"


def _requirement_name(requirement: str) -> str:
    match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", requirement)
    if match is None:
        raise ValueError(f"cannot parse wheel requirement: {requirement!r}")
    return _normalized_name(match.group(1))


def _wheel_metadata(path: Path) -> dict[str, Any]:
    with zipfile.ZipFile(path) as archive:
        metadata_names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        record_names = [name for name in archive.namelist() if name.endswith(".dist-info/RECORD")]
        if len(metadata_names) != 1 or len(record_names) != 1:
            raise ValueError(f"wheel has an invalid dist-info layout: {path.name}")
        message = BytesParser().parsebytes(archive.read(metadata_names[0]))
        name = message.get("Name")
        version = message.get("Version")
        if not name or not version:
            raise ValueError(f"wheel metadata is missing Name or Version: {path.name}")
        requirements = message.get_all("Requires-Dist", [])
        bad_members = [
            member
            for member in archive.namelist()
            if PureWheelPath(member).unsafe
        ]
        if bad_members:
            raise ValueError(f"wheel contains unsafe member paths: {path.name}")
    return {
        "name": name,
        "normalizedName": _normalized_name(name),
        "version": version,
        "requirements": requirements,
    }


class PureWheelPath:
    def __init__(self, value: str) -> None:
        self.value = value
        parts = value.replace("\\", "/").split("/")
        self.unsafe = value.startswith(("/", "\\")) or ".." in parts or any(
            ":" in part for part in parts
        )


def _load_lock(path: Path) -> dict[str, dict[str, str]]:
    locked: dict[str, dict[str, str]] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(
            r"([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s]+) "
            r"--hash=sha256:([0-9a-f]{64})\s+#\s+([A-Za-z0-9_.+-]+\.whl)",
            line,
        )
        if match is None:
            raise ValueError(f"dependency lock entry is not exact: {line}")
        name, version, digest, filename = match.groups()
        normalized = _normalized_name(name)
        if normalized in locked:
            raise ValueError(f"dependency lock repeats {normalized}")
        locked[normalized] = {
            "version": version,
            "sha256": digest,
            "filename": filename,
        }
    if not locked:
        raise ValueError("dependency lock is empty")
    return locked


def _source_digest(root: Path) -> tuple[str, int]:
    digest = sha256()
    count = 0
    for package_root in PACKAGE_ROOTS:
        directory = root / package_root
        for path in sorted(
            (candidate for candidate in directory.rglob("*") if candidate.is_file()),
            key=lambda candidate: candidate.relative_to(root).as_posix(),
        ):
            relative = path.relative_to(root)
            if any(
                part in {"__pycache__", "build", "dist"} or part.endswith(".egg-info")
                for part in relative.parts
            ):
                continue
            content_digest = sha256(path.read_bytes()).hexdigest()
            digest.update(relative.as_posix().encode("utf-8"))
            digest.update(b"\0")
            digest.update(content_digest.encode("ascii"))
            digest.update(b"\n")
            count += 1
    return digest.hexdigest(), count


def _wheel_set(wheel_dir: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    manifest_path = wheel_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "agent-web-wheel-set/1":
        raise ValueError("unsupported wheel-set manifest")
    records = manifest.get("files")
    if not isinstance(records, dict) or not records:
        raise ValueError("wheel-set manifest contains no files")
    actual = {path.name for path in wheel_dir.glob("*.whl")}
    if actual != set(records):
        raise ValueError("wheel files do not exactly match the wheel-set manifest")
    metadata: dict[str, dict[str, Any]] = {}
    for filename, record in records.items():
        if not isinstance(record, dict):
            raise ValueError(f"invalid wheel-set record: {filename}")
        path = wheel_dir / filename
        if path.stat().st_size != record.get("bytes") or _digest(path) != record.get("sha256"):
            raise ValueError(f"wheel does not match manifest: {filename}")
        metadata[filename] = _wheel_metadata(path)
    return metadata, manifest


def generate_release_evidence(
    wheel_dir: str | Path,
    output_dir: str | Path,
    *,
    root: Path = ROOT,
) -> dict[str, Any]:
    wheels = Path(wheel_dir).resolve(strict=True)
    output = Path(output_dir).resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite release evidence: {output}")
    output.mkdir(parents=True)
    metadata, wheel_manifest = _wheel_set(wheels)
    lock_path = root / "deploy/requirements.lock"
    locked = _load_lock(lock_path)
    manifest_path = wheels / "manifest.json"
    source_hash, source_files = _source_digest(root)
    subjects = [
        {
            "name": filename,
            "digest": {"sha256": wheel_manifest["files"][filename]["sha256"]},
        }
        for filename in sorted(metadata)
    ]
    set_fingerprint = sha256(
        "\n".join(f"{item['name']}:{item['digest']['sha256']}" for item in subjects).encode("utf-8")
    ).hexdigest()
    versions = {record["version"] for record in metadata.values()}
    release_version = next(iter(versions)) if len(versions) == 1 else "mixed"
    root_ref = f"pkg:generic/agent-web-wheel-set@{quote(release_version, safe='.-')}"

    components: list[dict[str, Any]] = []
    internal_refs: dict[str, str] = {}
    for filename in sorted(metadata):
        record = metadata[filename]
        reference = _purl(record["name"], record["version"])
        internal_refs[record["normalizedName"]] = reference
        components.append(
            {
                "type": "library",
                "bom-ref": reference,
                "name": record["name"],
                "version": record["version"],
                "purl": reference,
                "hashes": [{"alg": "SHA-256", "content": wheel_manifest["files"][filename]["sha256"]}],
                "properties": [{"name": "agent-web:artifact:filename", "value": filename}],
            }
        )
    external_refs: dict[str, str] = {}
    for name, lock_record in sorted(locked.items()):
        version = lock_record["version"]
        reference = _purl(name, version)
        external_refs[name] = reference
        components.append(
            {
                "type": "library",
                "bom-ref": reference,
                "name": name,
                "version": version,
                "purl": reference,
                "scope": "required",
                "hashes": [{"alg": "SHA-256", "content": lock_record["sha256"]}],
                "properties": [
                    {
                        "name": "agent-web:dependency:filename",
                        "value": lock_record["filename"],
                    }
                ],
            }
        )
    dependencies = [{"ref": root_ref, "dependsOn": sorted(internal_refs.values())}]
    for filename in sorted(metadata):
        record = metadata[filename]
        own_ref = internal_refs[record["normalizedName"]]
        required_refs: set[str] = set()
        for requirement in record["requirements"]:
            required_name = _requirement_name(requirement)
            target = internal_refs.get(required_name) or external_refs.get(required_name)
            if target is None:
                raise ValueError(
                    f"{record['name']} requirement is absent from wheels and lock: {required_name}"
                )
            required_refs.add(target)
        dependencies.append({"ref": own_ref, "dependsOn": sorted(required_refs)})
    dependencies.extend(
        {"ref": reference, "dependsOn": []}
        for reference in sorted(external_refs.values())
    )
    timestamp = f"{wheel_manifest['createdAt']}T00:00:00Z"
    sbom = {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid5(NAMESPACE_URL, set_fingerprint)}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "agent-web-release-evidence",
                        "version": "1",
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": "Agent Web wheel set",
                "version": release_version,
            },
        },
        "components": components,
        "dependencies": dependencies,
    }
    sbom_path = output / "agent-web.cdx.json"
    sbom_path.write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "urn:agent-web:build-type:pip-wheel-set:v1",
                "externalParameters": {
                    "command": [
                        "python", "-m", "pip", "wheel", "--no-deps", "--no-build-isolation",
                        "--wheel-dir", "dist", *PACKAGE_ROOTS,
                    ],
                    "packageRoots": list(PACKAGE_ROOTS),
                },
                "internalParameters": {
                    "provenanceCapture": "post-build-local-observation",
                    "sourceRevision": None,
                },
                "resolvedDependencies": [
                    {"uri": "file:deploy/requirements.lock", "digest": {"sha256": _digest(lock_path)}},
                    {"uri": "file:wheel-set/manifest.json", "digest": {"sha256": _digest(manifest_path)}},
                    {"uri": "file:workspace-package-sources", "digest": {"sha256": source_hash}},
                ],
            },
            "runDetails": {
                "builder": {"id": "urn:agent-web:builder:local-workstation:untrusted"},
                "metadata": {"invocationId": f"urn:sha256:{set_fingerprint}"},
                "byproducts": [
                    {"name": "agent-web.cdx.json", "digest": {"sha256": _digest(sbom_path)}}
                ],
            },
        },
    }
    provenance_path = output / "agent-web.provenance.json"
    provenance_path.write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    claims = {
        "schema": "agent-web-release-claims/1",
        "artifactDigestsVerified": True,
        "wheelMetadataParsed": True,
        "cycloneDxVersion": "1.7",
        "slsaPredicateVersion": "1",
        "sourceMaterialFiles": source_files,
        "provenanceSigned": False,
        "provenanceGeneratedByTrustedBuildPlatform": False,
        "isolatedBuildVerified": False,
        "sourceRevisionRecorded": False,
        "containerImageIncluded": False,
        "runtimeDependencyArtifactsHashLocked": True,
        "hashLockTarget": "CPython 3.13 / Linux x86_64",
        "slsaBuildLevelClaimed": 0,
        "notice": (
            "This local, post-build statement binds observed wheel digests and metadata. "
            "It is not a signature, trusted-builder attestation, source-revision proof, "
            "container SBOM, or SLSA Build Level claim."
        ),
    }
    claims_path = output / "release-claims.json"
    claims_path.write_text(json.dumps(claims, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    evidence_manifest = {
        "schema": "agent-web-release-evidence/1",
        "wheelSet": subjects,
        "evidence": {
            filename: {"sha256": _digest(output / filename), "bytes": (output / filename).stat().st_size}
            for filename in EVIDENCE_FILES
        },
    }
    manifest_output = output / "evidence-manifest.json"
    manifest_output.write_text(
        json.dumps(evidence_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "status": "created",
        "output": str(output),
        "wheels": len(subjects),
        "lockedDependencies": len(locked),
        "provenanceSigned": False,
        "slsaBuildLevelClaimed": 0,
    }
