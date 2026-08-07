"""Run every Agent Web security, conformance, and interoperability gate."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def run(label: str, command: list[str], cwd: Path = ROOT) -> None:
    print(f"\n== {label} ==", flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def main() -> int:
    npm = shutil.which("npm.cmd") or shutil.which("npm")
    if npm is None:
        raise RuntimeError("npm is required for TypeScript verification")

    python_suites = [
        ("libagentweb Python", ROOT / "libagentweb/python/tests"),
        ("publisher security", ROOT / "agent-web-server/python/tests"),
        ("Moltbook site", ROOT / "sites/moltbook/python/tests"),
        ("Forecast bridge", ROOT / "sites/forecast/python/tests"),
        ("Registry search", ROOT / "sites/registry/python/tests"),
        ("graphical browser daemon", ROOT / "agent-web-browser/python/tests"),
        ("secure live network", ROOT / "acceptance/python"),
    ]
    for label, suite in python_suites:
        run(
            label,
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                str(suite),
                "-v",
            ],
        )

    run("Python dependency integrity", [sys.executable, "-m", "pip", "check"])
    run(
        "isolated deployment contract",
        [sys.executable, str(ROOT / "scripts/validate_deployment.py")],
    )
    run(
        "monitoring and alerting contract",
        [sys.executable, str(ROOT / "scripts/validate_observability.py")],
    )
    run(
        "Kubernetes network policy contract",
        [sys.executable, str(ROOT / "scripts/validate_network_policy.py")],
    )
    run(
        "Vault managed-signing deployment contract",
        [sys.executable, str(ROOT / "scripts/validate_vault_deployment.py")],
    )
    run(
        "public-beta manifest contract",
        [
            sys.executable,
            str(ROOT / "scripts/public_beta_gate.py"),
            "--manifest",
            str(ROOT / "deploy/public-beta.example.json"),
            "--validate-only",
        ],
    )
    run(
        "external review bundle contract",
        [sys.executable, str(ROOT / "scripts/validate_review_bundle.py")],
    )
    run(
        "libagentweb TypeScript types",
        [npm, "run", "typecheck"],
        ROOT / "libagentweb",
    )
    run(
        "libagentweb TypeScript tests",
        [npm, "test"],
        ROOT / "libagentweb",
    )
    run(
        "graphical browser tests",
        [npm, "test"],
        ROOT / "agent-web-browser",
    )
    run(
        "graphical browser production build",
        [npm, "run", "build"],
        ROOT / "agent-web-browser",
    )
    run(
        "graphical browser dependency audit",
        [npm, "audit", "--audit-level=high"],
        ROOT / "agent-web-browser",
    )
    run(
        "independent-process federation",
        [sys.executable, str(ROOT / "scripts/independent_federation.py")],
    )

    print("\nAll Agent Web acceptance gates passed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
