"""Render strict Prometheus configuration from an operator-owned JSON manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, Mapping
from urllib.parse import urlsplit


SCHEMA = "agent-web-monitoring/1"
NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


def render(document: Mapping[str, Any]) -> str:
    if document.get("schema") != SCHEMA:
        raise ValueError("unsupported monitoring manifest")
    publishers = document.get("publishers")
    if not isinstance(publishers, list) or not publishers:
        raise ValueError("monitoring manifest requires publishers")
    alertmanagers = document.get("alertmanagers")
    if not isinstance(alertmanagers, list) or not alertmanagers:
        raise ValueError("monitoring manifest requires alertmanagers")
    lines = [
        "global:",
        "  scrape_interval: 30s",
        "  evaluation_interval: 30s",
        "rule_files:",
        "  - /etc/prometheus/rules.yml",
        "alerting:",
        "  alertmanagers:",
        "    - static_configs:",
        "        - targets:",
    ]
    for target in alertmanagers:
        lines.append(f"            - {_quote_target(target)}")
    lines.append("scrape_configs:")
    names: set[str] = set()
    for item in publishers:
        if not isinstance(item, Mapping):
            raise ValueError("publisher monitoring entry must be an object")
        name = item.get("name")
        if not isinstance(name, str) or not NAME.fullmatch(name) or name in names:
            raise ValueError("publisher monitoring names must be unique slugs")
        names.add(name)
        parsed = urlsplit(str(item.get("metricsUrl", "")))
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path != "/metrics"
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("metricsUrl must be an HTTPS /metrics URL")
        token_file = item.get("metricsTokenFile")
        if not isinstance(token_file, str) or not token_file.startswith(
            "/run/agent-web/metrics/"
        ):
            raise ValueError("metricsTokenFile must use the mounted metrics path")
        port = parsed.port or 443
        target = f"{parsed.hostname}:{port}"
        lines.extend(
            [
                f"  - job_name: {json.dumps('agent-web-' + name)}",
                "    scheme: https",
                "    metrics_path: /metrics",
                "    authorization:",
                "      type: Bearer",
                f"      credentials_file: {json.dumps(token_file)}",
                "    tls_config:",
                f"      server_name: {json.dumps(parsed.hostname)}",
            ]
        )
        ca_file = item.get("caFile")
        if ca_file is not None:
            if not isinstance(ca_file, str) or not ca_file.startswith(
                "/run/agent-web/metrics/"
            ):
                raise ValueError("caFile must use the mounted metrics path")
            lines.append(f"      ca_file: {json.dumps(ca_file)}")
        lines.extend(
            [
                "    static_configs:",
                "      - targets:",
                f"          - {json.dumps(target)}",
            ]
        )
    return "\n".join(lines) + "\n"


def _quote_target(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9.-]+:[0-9]{1,5}", value
    ):
        raise ValueError("alertmanager target must be HOST:PORT")
    port = int(value.rsplit(":", 1)[1])
    if port < 1 or port > 65535:
        raise ValueError("alertmanager port is invalid")
    return json.dumps(value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    source = Path(args.manifest)
    document = json.loads(source.read_text(encoding="utf-8"))
    content = render(document)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
