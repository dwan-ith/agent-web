"""Validate the narrow containment policy for an unfixed transitive advisory."""

from __future__ import annotations

import ast
from importlib.metadata import distribution, version
import json
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_SOURCE_ROOTS = (
    ROOT / "libagentweb/python/src",
    ROOT / "agent-web-server/python/src",
    ROOT / "sites/moltbook/python/src",
    ROOT / "sites/forecast/python/src",
    ROOT / "sites/registry/python/src",
    ROOT / "line-mode-agent-browser/python/src",
    ROOT / "agent-web-browser/python/src",
)
EXPECTED_ANP_VERSION = "0.9.2"
EXPECTED_ECDSA_VERSION = "0.19.2"
ADVISORY = "PYSEC-2026-1325"


def _imports_ecdsa(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(
            alias.name.split(".", 1)[0] == "ecdsa" for alias in node.names
        ):
            return True
        if isinstance(node, ast.ImportFrom) and (
            node.module or ""
        ).split(".", 1)[0] == "ecdsa":
            return True
        if isinstance(node, ast.Call) and node.args:
            function = node.func
            dynamic_import = (
                isinstance(function, ast.Name) and function.id == "__import__"
            ) or (
                isinstance(function, ast.Attribute)
                and function.attr == "import_module"
            )
            first = node.args[0]
            if (
                dynamic_import
                and isinstance(first, ast.Constant)
                and isinstance(first.value, str)
                and first.value.split(".", 1)[0] == "ecdsa"
            ):
                return True
    return False


def _anp_sources() -> Iterable[Path]:
    package = distribution("anp")
    for relative in package.files or ():
        value = Path(str(relative))
        if value.suffix == ".py" and value.parts and value.parts[0] == "anp":
            yield Path(package.locate_file(relative))


def main() -> int:
    if version("anp") != EXPECTED_ANP_VERSION:
        raise ValueError("ANP version changed; re-audit the ecdsa advisory boundary")
    if version("ecdsa") != EXPECTED_ECDSA_VERSION:
        raise ValueError("ecdsa version changed; re-audit the advisory boundary")
    imported_by: list[str] = []
    for path in _anp_sources():
        if _imports_ecdsa(path):
            imported_by.append(f"anp:{path.name}")
    for root in RUNTIME_SOURCE_ROOTS:
        for path in root.rglob("*.py"):
            if _imports_ecdsa(path):
                imported_by.append(path.relative_to(ROOT).as_posix())
    if imported_by:
        raise ValueError(
            "unfixed python-ecdsa primitive became reachable: "
            + ", ".join(sorted(imported_by))
        )
    print(
        json.dumps(
            {
                "status": "passed",
                "advisory": ADVISORY,
                "dependency": f"ecdsa=={EXPECTED_ECDSA_VERSION}",
                "requiredBy": f"anp=={EXPECTED_ANP_VERSION}",
                "runtimeImportsFound": False,
                "disposition": (
                    "contained transitive dependency; do not enable it for signing "
                    "or key agreement"
                ),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
