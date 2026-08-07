"""Static checks for the monitoring and alerting deployment contract."""

from __future__ import annotations

import json
from pathlib import Path

from render_monitoring_config import render


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    root = ROOT / "deploy" / "observability"
    manifest = json.loads(
        (root / "monitoring.example.json").read_text(encoding="utf-8")
    )
    rendered = render(manifest)
    if "insecure_skip_verify" in rendered:
        raise ValueError("monitoring must verify publisher TLS certificates")
    if rendered.count("credentials_file:") != len(manifest["publishers"]):
        raise ValueError("each publisher requires its own metrics credential")
    rules = (root / "rules.yml").read_text(encoding="utf-8")
    expected_alerts = {
        "AgentWebPublisherDown",
        "AgentWebPublisherNotReady",
        "AgentWebHighServerErrorRate",
        "AgentWebSecurityDenialSpike",
        "AgentWebHighP95Latency",
        "AgentWebMaintenanceStuck",
    }
    missing = {name for name in expected_alerts if f"alert: {name}" not in rules}
    if missing:
        raise ValueError(f"monitoring rules are missing alerts: {sorted(missing)}")
    alertmanager = (root / "alertmanager.yml").read_text(encoding="utf-8")
    if "url_file:" not in alertmanager or "send_resolved: true" not in alertmanager:
        raise ValueError("alert delivery must use a mounted URL and send resolutions")
    compose = json.loads(
        (ROOT / "deploy" / "compose.observability.json").read_text(
            encoding="utf-8"
        )
    )
    if set(compose.get("services", {})) != {"prometheus", "alertmanager"}:
        raise ValueError("observability compose services are incomplete")
    for name, service in compose["services"].items():
        if service.get("read_only") is not True:
            raise ValueError(f"{name} root filesystem is writable")
        if service.get("cap_drop") != ["ALL"]:
            raise ValueError(f"{name} retains Linux capabilities")
        if "no-new-privileges:true" not in service.get("security_opt", []):
            raise ValueError(f"{name} permits privilege escalation")
    print(
        json.dumps(
            {
                "status": "passed",
                "publishers": len(manifest["publishers"]),
                "alerts": sorted(expected_alerts),
                "tlsVerification": "required",
                "notificationDelivery": "requires operator webhook secret",
                "runtimeExecution": "not asserted by this static check",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
