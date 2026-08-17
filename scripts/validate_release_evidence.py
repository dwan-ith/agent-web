"""Generate and independently verify the release-evidence contract."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from release_evidence import EVIDENCE_FILES, generate_release_evidence


ROOT = Path(__file__).resolve().parents[1]
WHEELS = ROOT / "artifacts/wheels-20260813-registry-federation"


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def main() -> int:
    with TemporaryDirectory() as temporary:
        output = Path(temporary) / "evidence"
        result = generate_release_evidence(WHEELS, output)
        manifest = json.loads((output / "evidence-manifest.json").read_text(encoding="utf-8"))
        for filename in EVIDENCE_FILES:
            record = manifest["evidence"][filename]
            path = output / filename
            if record["sha256"] != _digest(path) or record["bytes"] != path.stat().st_size:
                raise ValueError(f"evidence manifest mismatch: {filename}")
        wheel_manifest = json.loads((WHEELS / "manifest.json").read_text(encoding="utf-8"))
        expected_subjects = [
            {"name": name, "digest": {"sha256": wheel_manifest["files"][name]["sha256"]}}
            for name in sorted(wheel_manifest["files"])
        ]
        if manifest["wheelSet"] != expected_subjects:
            raise ValueError("evidence manifest does not bind the complete wheel set")
        provenance = json.loads((output / "agent-web.provenance.json").read_text(encoding="utf-8"))
        if (
            provenance.get("_type") != "https://in-toto.io/Statement/v1"
            or provenance.get("predicateType") != "https://slsa.dev/provenance/v1"
            or provenance.get("subject") != expected_subjects
        ):
            raise ValueError("provenance statement does not bind the wheel subjects")
        sbom = json.loads((output / "agent-web.cdx.json").read_text(encoding="utf-8"))
        if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.7":
            raise ValueError("SBOM is not CycloneDX 1.7")
        component_refs = {component["bom-ref"] for component in sbom.get("components", [])}
        wheel_refs = {
            component["bom-ref"]
            for component in sbom["components"]
            if any(prop.get("name") == "agent-web:artifact:filename" for prop in component.get("properties", []))
        }
        if len(expected_subjects) != 8:
            raise ValueError("release wheel set must include all eight Agent Web packages")
        if not any(
            subject["name"].startswith("native_knowledge_agent_web_site-")
            for subject in expected_subjects
        ):
            raise ValueError("release wheel set omits the native Agent Web site")
        if len(wheel_refs) != len(expected_subjects) or len(component_refs) < 50:
            raise ValueError("SBOM omits wheels or locked runtime dependencies")
        locked_components = [
            component
            for component in sbom["components"]
            if any(
                prop.get("name") == "agent-web:dependency:filename"
                for prop in component.get("properties", [])
            )
        ]
        if len(locked_components) != 51 or any(
            len(component.get("hashes", [])) != 1 for component in locked_components
        ):
            raise ValueError("SBOM does not bind every runtime dependency artifact hash")
        dependency_refs = {entry["ref"] for entry in sbom.get("dependencies", [])}
        if not wheel_refs.issubset(dependency_refs):
            raise ValueError("SBOM dependency graph omits a wheel component")
        claims = json.loads((output / "release-claims.json").read_text(encoding="utf-8"))
        required_false = {
            "provenanceSigned",
            "provenanceGeneratedByTrustedBuildPlatform",
            "isolatedBuildVerified",
            "sourceRevisionRecorded",
            "containerImageIncluded",
        }
        if any(claims.get(name) is not False for name in required_false):
            raise ValueError("local evidence overstates a trust claim")
        if claims.get("slsaBuildLevelClaimed") != 0:
            raise ValueError("post-build local evidence must not claim a SLSA Build Level")
        if claims.get("runtimeDependencyArtifactsHashLocked") is not True:
            raise ValueError("release claims omit the runtime artifact hash lock")
    print(
        json.dumps(
            {
                "status": "passed",
                "wheels": result["wheels"],
                "cycloneDx": "1.7",
                "slsaPredicate": "v1",
                "trustedProvenanceClaimed": False,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
