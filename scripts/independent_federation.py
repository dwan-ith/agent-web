"""Prove Agent Web federation across independently launched OS processes."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _provision(root: Path) -> Path:
    from agent_web_server import (
        active_identity_paths,
        find_free_port,
        generate_local_tls,
        provision_identity_lifecycle,
    )
    import certifi

    ports: list[int] = []
    while len(ports) < 4:
        port = find_free_port()
        if port not in ports:
            ports.append(port)
    identities: dict[str, dict[str, Any]] = {}
    for name, ad_path, port in zip(
        ("moltbook", "forecast", "registry", "browser"),
        (
            "/moltbook/ad.json",
            "/forecast/ad.json",
            "/registry/ad.json",
            "/browser/ad.json",
        ),
        ports,
    ):
        base_url = f"https://localhost:{port}"
        directory = root / "operators" / name / "identity"
        identity = provision_identity_lifecycle(
            directory=directory,
            base_url=base_url,
            agent_name=name,
            agent_description_path=ad_path,
        )
        did_path, key_path = active_identity_paths(directory)
        identities[name] = {
            "baseUrl": base_url,
            "did": identity.did,
            "identityDirectory": str(directory),
            "didPath": str(did_path),
            "keyPath": str(key_path),
            "port": port,
        }

    tls = generate_local_tls(root / "tls")
    combined_ca = root / "tls" / "combined-ca-bundle.pem"
    combined_ca.write_bytes(
        Path(certifi.where()).read_bytes()
        + b"\n"
        + tls.ca_certificate.read_bytes()
    )
    now = datetime.now(timezone.utc)
    static_records = {
        "bengaluru": {
            "slug": "bengaluru",
            "location": "Bengaluru",
            "temperatureC": 24.5,
            "condition": "Deterministic independent-process fixture",
            "observedAt": _timestamp(now),
            "retrievedAt": _timestamp(now),
            "validThrough": _timestamp(now + timedelta(minutes=10)),
            "source": "https://api.open-meteo.com/independent-process-fixture",
            "sourceProvider": "Open-Meteo fixture",
        }
    }
    forecast_data = root / "operators" / "forecast" / "static-data.json"
    forecast_data.parent.mkdir(parents=True, exist_ok=True)
    forecast_data.write_text(
        json.dumps(static_records, indent=2),
        encoding="utf-8",
    )
    config = {
        "identities": identities,
        "tls": {
            "ca": str(tls.ca_certificate),
            "caBundle": str(combined_ca),
            "certificate": str(tls.certificate),
            "privateKey": str(tls.private_key),
        },
        "forecastData": str(forecast_data),
        "root": str(root),
    }
    config_path = root / "federation.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return config_path


def _server_command(
    module: str,
    identity: dict[str, Any],
    tls: dict[str, str],
    extra: list[str],
) -> list[str]:
    return [
        sys.executable,
        "-m",
        module,
        "--host",
        "127.0.0.1",
        "--port",
        str(identity["port"]),
        "--base-url",
        identity["baseUrl"],
        "--identity-directory",
        identity["identityDirectory"],
        "--tls-certificate",
        tls["certificate"],
        "--tls-private-key",
        tls["privateKey"],
        *extra,
    ]


def _wait_ready(
    url: str,
    *,
    context: ssl.SSLContext,
    processes: list[subprocess.Popen[str]],
    deadline_seconds: float = 20,
) -> None:
    import httpx

    deadline = monotonic() + deadline_seconds
    last_error: Exception | None = None
    while monotonic() < deadline:
        for process in processes:
            if process.poll() is not None:
                raise RuntimeError(
                    f"publisher process {process.pid} exited with {process.returncode}"
                )
        try:
            with httpx.Client(verify=context, timeout=1, trust_env=False) as client:
                response = client.get(url)
                if response.status_code == 200:
                    return
        except Exception as exc:
            last_error = exc
        sleep(0.05)
    raise RuntimeError(f"publisher did not become ready: {url}: {last_error}")


def _run_child(config_path: Path) -> int:
    # This process starts after its environment trusts the generated CA.
    from agent_web_server import AuthorizationStore
    import httpx
    from libagentweb import AgentBrowser

    config = json.loads(config_path.read_text(encoding="utf-8"))
    identities = config["identities"]
    tls = config["tls"]
    root = Path(config["root"])
    moltbook = identities["moltbook"]
    forecast = identities["forecast"]
    registry = identities["registry"]
    browser_identity = identities["browser"]

    authorization_database = (
        root / "operators" / "moltbook" / "authorization.db"
    )
    authorization_database.parent.mkdir(parents=True, exist_ok=True)
    grants = AuthorizationStore(authorization_database)
    try:
        grants.grant(
            subject_did=browser_identity["did"],
            action="moltbook:create_thread",
            resource=f"{moltbook['baseUrl']}/moltbook/resources/index.json",
            note="independent-process federation browser",
        )
        grants.grant(
            subject_did=browser_identity["did"],
            action="moltbook:create_reply",
            resource=f"{moltbook['baseUrl']}/moltbook/resources/threads/",
            scope_type="prefix",
            note="independent-process federation browser",
        )
    finally:
        grants.close()

    moltbook_root = root / "operators" / "moltbook"
    forecast_root = root / "operators" / "forecast"
    registry_root = root / "operators" / "registry"
    commands = [
        _server_command(
            "moltbook_site.cli",
            moltbook,
            tls,
            [
                "--database",
                str(moltbook_root / "content.db"),
                "--nonce-database",
                str(moltbook_root / "nonces.db"),
                "--authorization-database",
                str(authorization_database),
                "--forecast-entrypoint",
                f"{forecast['baseUrl']}/forecast/resources/index.json",
            ],
        ),
        _server_command(
            "forecast_site.cli",
            forecast,
            tls,
            [
                "--nonce-database",
                str(forecast_root / "nonces.db"),
                "--moltbook-entrypoint",
                f"{moltbook['baseUrl']}/moltbook/resources/index.json",
                "--static-data",
                config["forecastData"],
            ],
        ),
        _server_command(
            "registry_site",
            registry,
            tls,
            [
                "serve",
            ],
        ),
        _server_command(
            "agent_web_browser.cli",
            browser_identity,
            tls,
            ["--allow-private-network"],
        ),
    ]
    # registry_site expects its command immediately after the module name.
    registry_command = commands[2]
    serve_index = registry_command.index("serve")
    registry_command.pop(serve_index)
    registry_command.insert(3, "serve")
    registry_command.extend(
        [
            "--database",
            str(registry_root / "registry.db"),
            "--nonce-database",
            str(registry_root / "nonces.db"),
        ]
    )

    creationflags = (
        subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    )
    processes: list[subprocess.Popen[str]] = []
    try:
        for command in commands:
            processes.append(
                subprocess.Popen(
                    command,
                    cwd=ROOT,
                    env=os.environ.copy(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    creationflags=creationflags,
                )
            )
        ca_context = ssl.create_default_context(cafile=tls["ca"])
        for url in (
            f"{moltbook['baseUrl']}/health",
            f"{forecast['baseUrl']}/health",
            f"{registry['baseUrl']}/health",
            f"{browser_identity['baseUrl']}/",
        ):
            _wait_ready(url, context=ca_context, processes=processes)

        indexed: list[dict[str, Any]] = []
        for description_url in (
            f"{moltbook['baseUrl']}/moltbook/ad.json",
            f"{forecast['baseUrl']}/forecast/ad.json",
        ):
            command = [
                sys.executable,
                "-m",
                "registry_site",
                "index",
                "--database",
                str(registry_root / "registry.db"),
                "--agent-description-url",
                description_url,
                "--identity-directory",
                registry["identityDirectory"],
                "--allow-private-network",
            ]
            result = subprocess.run(
                command,
                cwd=ROOT,
                env=os.environ.copy(),
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
                creationflags=creationflags,
            )
            indexed.append(json.loads(result.stdout))

        browser = AgentBrowser(
            f"{moltbook['baseUrl']}/moltbook/ad.json",
            did_document_path=browser_identity["didPath"],
            private_key_path=browser_identity["keyPath"],
            allowed_origins={forecast["baseUrl"]},
            allow_private_networks=True,
        )
        created = browser.call(
            "create_thread",
            {
                "title": "Independent operator process proof",
                "body": "Created across separate TLS publisher and browser processes.",
            },
            confirmed=True,
        )
        forecast_browser = AgentBrowser(
            f"{forecast['baseUrl']}/forecast/ad.json",
            did_document_path=browser_identity["didPath"],
            private_key_path=browser_identity["keyPath"],
            allow_private_networks=True,
        )
        weather = forecast_browser.call(
            "get_forecast",
            {"location": "bengaluru"},
        )
        registry_browser = AgentBrowser(
            f"{registry['baseUrl']}/registry/ad.json",
            did_document_path=browser_identity["didPath"],
            private_key_path=browser_identity["keyPath"],
            allow_private_networks=True,
        )
        search = registry_browser.call(
            "search",
            {"query": "Bengaluru", "limit": 10},
        )
        with httpx.Client(
            verify=ca_context,
            timeout=10,
            trust_env=False,
        ) as client:
            graphical = client.post(
                f"{browser_identity['baseUrl']}/api/connect",
                json={
                    "agentDescriptionUrl": (
                        f"{moltbook['baseUrl']}/moltbook/ad.json"
                    )
                },
            )
            graphical.raise_for_status()

        if len({process.pid for process in processes}) != 4:
            raise RuntimeError("publisher processes do not have distinct PIDs")
        if not all(process.poll() is None for process in processes):
            raise RuntimeError("a publisher process exited during federation proof")
        proof = {
            "status": "passed",
            "isolation": "four independently launched OS processes",
            "processes": {
                name: process.pid
                for name, process in zip(
                    ("moltbook", "forecast", "registry", "graphicalBrowser"),
                    processes,
                )
            },
            "operatorDirectories": {
                name: str(root / "operators" / name)
                for name in ("moltbook", "forecast", "registry", "browser")
            },
            "identityLifecycle": "manifest generation 1 per operator",
            "authorization": {
                "caller": created["data"]["author"],
                "policy": "explicit scoped operator grant",
            },
            "forecast": {
                "publisher": weather["provenance"]["publisher"],
                "temperatureC": weather["data"]["temperatureC"],
                "providerMode": "explicit deterministic fixture",
            },
            "registry": {
                "indexed": indexed,
                "searchResults": search["data"]["count"],
                "sourcePublisher": (
                    search["data"]["results"][0]["source"]["publisher"]
                ),
                "sourceProofPreserved": bool(
                    search["data"]["results"][0]["source"]["proof"]
                ),
            },
            "graphicalBrowser": {
                "connectStatus": graphical.status_code,
                "callerDid": graphical.json()["status"]["callerDid"],
            },
        }
        print(json.dumps(proof, indent=2))
        return 0
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for process in reversed(processes):
            try:
                process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--child-config", type=Path)
    args = parser.parse_args()
    if args.child_config:
        return _run_child(args.child_config)

    with TemporaryDirectory(prefix="agent-web-federation-") as value:
        config_path = _provision(Path(value))
        config = json.loads(config_path.read_text(encoding="utf-8"))
        environment = os.environ.copy()
        environment["SSL_CERT_FILE"] = config["tls"]["caBundle"]
        environment["REQUESTS_CA_BUNDLE"] = config["tls"]["caBundle"]
        environment["NODE_EXTRA_CA_CERTS"] = config["tls"]["ca"]
        environment["NO_PROXY"] = "localhost,127.0.0.1"
        result = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--child-config",
                str(config_path),
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "independent federation failed\n"
                f"stdout:\n{result.stdout}\n"
                f"stderr:\n{result.stderr}"
            )
        print(result.stdout.strip())
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
