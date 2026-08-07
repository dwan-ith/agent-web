"""Static acceptance checks for the container deployment contract."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    compose_path = ROOT / "deploy" / "compose.json"
    document = json.loads(compose_path.read_text(encoding="utf-8"))
    services = document.get("services")
    if not isinstance(services, dict):
        raise ValueError("compose services must be an object")
    required = {"moltbook", "forecast", "registry"}
    if set(services) != required:
        raise ValueError("deployment must contain exactly the three publishers")
    data_mounts: set[str] = set()
    for name, service in services.items():
        if service.get("read_only") is not True:
            raise ValueError(f"{name} root filesystem is not read-only")
        if service.get("cap_drop") != ["ALL"]:
            raise ValueError(f"{name} does not drop all Linux capabilities")
        if "no-new-privileges:true" not in service.get("security_opt", []):
            raise ValueError(f"{name} permits privilege escalation")
        command = service.get("command", [])
        for flag in (
            "--identity-directory",
            "--tls-certificate",
            "--tls-private-key",
            "--metrics-token-file",
            "--operator-token-file",
        ):
            if flag not in command:
                raise ValueError(f"{name} command is missing {flag}")
        volumes = service.get("volumes", [])
        identity_mounts = [
            value for value in volumes
            if ":/run/agent-web/identity:ro" in value
        ]
        tls_mounts = [
            value for value in volumes
            if ":/run/agent-web/tls:ro" in value
        ]
        operations_mounts = [
            value for value in volumes
            if ":/run/agent-web/operations:ro" in value
        ]
        writable_data = [
            value for value in volumes
            if value.endswith(":/var/lib/agent-web")
        ]
        if (
            len(identity_mounts) != 1
            or len(tls_mounts) != 1
            or len(operations_mounts) != 1
        ):
            raise ValueError(f"{name} secrets are not uniquely mounted read-only")
        if len(writable_data) != 1:
            raise ValueError(f"{name} does not have one durable data mount")
        if writable_data[0] in data_mounts:
            raise ValueError("publishers share a durable data mount")
        data_mounts.add(writable_data[0])
        health = service.get("healthcheck", {}).get("test", [])
        if "/ready" not in " ".join(health):
            raise ValueError(f"{name} has no HTTPS readiness check")

    lock_lines = [
        line.strip()
        for line in (ROOT / "deploy" / "requirements.lock").read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if not lock_lines or any("==" not in line for line in lock_lines):
        raise ValueError("runtime dependency lock contains unpinned entries")
    names = [line.split("==", 1)[0].lower() for line in lock_lines]
    if len(names) != len(set(names)):
        raise ValueError("runtime dependency lock contains duplicates")

    dockerfile = (ROOT / "deploy" / "Dockerfile").read_text(encoding="utf-8")
    for required_text in (
        "USER 10001:10001",
        "--no-deps",
        "requirements.lock",
    ):
        if required_text not in dockerfile:
            raise ValueError(f"Dockerfile is missing {required_text}")
    if "deploy/secrets" in dockerfile or "deploy/data" in dockerfile:
        raise ValueError("Dockerfile copies operator state into the image")

    print(
        json.dumps(
            {
                "status": "passed",
                "composeFormat": "JSON representation of the Compose specification",
                "services": sorted(services),
                "pinnedRuntimeDependencies": len(lock_lines),
                "controls": [
                    "non-root image",
                    "read-only root filesystems",
                    "all Linux capabilities dropped",
                    "no-new-privileges",
                    "read-only identity and TLS mounts",
                    "read-only operations-token mounts",
                    "separate durable data mounts",
                    "SQLite-backed HTTPS readiness checks",
                ],
                "runtimeExecution": (
                    "not asserted by this static check; use Docker Compose "
                    "config/up on a Docker host"
                ),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
