"""Run every Agent Web security, conformance, and interoperability gate."""

from __future__ import annotations

from pathlib import Path
import os
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def run(
    label: str,
    command: list[str],
    cwd: Path = ROOT,
) -> None:
    print(f"\n== {label} ==", flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def main() -> int:
    # shutil.which resolves npm/npm.cmd/npm.exe per platform via PATHEXT.
    npm = shutil.which("npm")
    if npm is None:
        raise RuntimeError("npm is required for TypeScript verification")

    python_suites = [
        ("libagentweb Python", ROOT / "libagentweb/python/tests"),
        ("publisher security", ROOT / "agent-web-server/python/tests"),
        ("Moltbook site", ROOT / "sites/moltbook/python/tests"),
        ("Forecast bridge", ROOT / "sites/forecast/python/tests"),
        ("Registry search", ROOT / "sites/registry/python/tests"),
        ("native agent-only site", ROOT / "sites/native-knowledge/python/tests"),
        ("line-mode browser CLI", ROOT / "line-mode-agent-browser/python/tests"),
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

    run(
        "Python source compilation",
        [sys.executable, "-m", "compileall", "-q", str(ROOT)],
    )

    run("Python dependency integrity", [sys.executable, "-m", "pip", "check"])
    run(
        "unfixed dependency advisory containment",
        [sys.executable, str(ROOT / "scripts/validate_dependency_policy.py")],
    )
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
        "Kubernetes workload contract",
        [sys.executable, str(ROOT / "scripts/validate_kubernetes_workloads.py")],
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
        "release SBOM and provenance contract",
        [sys.executable, str(ROOT / "scripts/validate_release_evidence.py")],
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
    if os.environ.get("AGENT_WEB_SKIP_NPM_AUDIT") != "1":
        run(
            "graphical browser dependency audit",
            [npm, "audit", "--audit-level=high"],
            ROOT / "agent-web-browser",
        )
    else:
        print(
            "\n== graphical browser dependency audit ==\n"
            "skipped: AGENT_WEB_SKIP_NPM_AUDIT=1 (air-gapped mode)",
            flush=True,
        )
    run(
        "independent-process federation",
        [sys.executable, str(ROOT / "scripts/independent_federation.py")],
    )

    print("\nAll Agent Web acceptance gates passed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
