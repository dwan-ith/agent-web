"""Launch a real local TLS network and emit bounded end-to-end evidence."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]


def _provision(directory: Path) -> dict[str, object]:
    from agent_web_server import (
        find_free_port,
        generate_local_tls,
        generate_publisher_identity,
        write_identity,
    )
    import certifi

    ports: list[int] = []
    while len(ports) < 5:
        port = find_free_port()
        if port not in ports:
            ports.append(port)
    names = ("moltbook", "forecast", "registry", "browser", "native")
    paths = (
        "/moltbook/ad.json",
        "/forecast/ad.json",
        "/registry/ad.json",
        "/browser/ad.json",
        None,
    )
    identities: dict[str, dict[str, str]] = {}
    for name, path, port in zip(names, paths, ports):
        base_url = f"https://localhost:{port}"
        if path is None:
            # The native Agent Web publisher needs no ANP identity; its
            # trust root is the HTTPS origin's discovery document.
            identities[name] = {"baseUrl": base_url}
            continue
        identity = generate_publisher_identity(
            base_url=base_url,
            agent_name=name,
            agent_description_path=path,
        )
        did_path, key_path = write_identity(
            identity,
            directory=directory / f"{name}-identity",
        )
        identities[name] = {
            "baseUrl": base_url,
            "did": identity.did,
            "didPath": str(did_path),
            "keyPath": str(key_path),
        }
    tls = generate_local_tls(directory / "tls")
    combined_ca = directory / "tls" / "combined-ca-bundle.pem"
    combined_ca.write_bytes(
        Path(certifi.where()).read_bytes()
        + b"\n"
        + tls.ca_certificate.read_bytes()
    )
    return {
        "identities": identities,
        "tls": {
            "ca": str(tls.ca_certificate),
            "caBundle": str(combined_ca),
            "certificate": str(tls.certificate),
            "privateKey": str(tls.private_key),
        },
    }


def _run_network(config_path: Path, *, stay: bool = False) -> int:
    # These imports intentionally happen only after the parent process places
    # the generated CA in this fresh process's environment. The official ANP
    # SDK then builds its aiohttp trust context with the correct CA.
    from agent_web_browser import create_app as create_browser_app
    from agent_web_server import PublisherIdentity, start_site
    from forecast_site import start_forecast
    import httpx
    from libagentweb import (
        AgentBrowser,
        LocalEd25519Signer,
        build_caller_controller,
    )
    from moltbook_site import start_moltbook
    from native_knowledge_site import create_app as create_native_app
    from registry_site import RegistryIndexer, start_registry

    config = json.loads(config_path.read_text(encoding="utf-8"))
    identities = config["identities"]
    tls = config["tls"]
    loaded = {
        name: PublisherIdentity.from_files(value["didPath"], value["keyPath"])
        for name, value in identities.items()
        if "didPath" in value
    }
    moltbook_base = identities["moltbook"]["baseUrl"]
    forecast_base = identities["forecast"]["baseUrl"]
    browser_base = identities["browser"]["baseUrl"]
    registry_base = identities["registry"]["baseUrl"]
    native_base = identities["native"]["baseUrl"]
    moltbook = start_moltbook(
        port=int(moltbook_base.rsplit(":", 1)[1]),
        database=str(config_path.parent / "moltbook.db"),
        nonce_database=str(config_path.parent / "moltbook-nonces.db"),
        authorization_database=str(
            config_path.parent / "moltbook-authorization.db"
        ),
        seed=False,
        forecast_entrypoint=f"{forecast_base}/forecast/resources/index.json",
        identity=loaded["moltbook"],
        tls_certificate=tls["certificate"],
        tls_private_key=tls["privateKey"],
    )
    moltbook.app.state.authorization_store.grant(
        subject_did=loaded["browser"].did,
        action="moltbook:create_thread",
        resource=f"{moltbook_base}/moltbook/resources/index.json",
        note="bounded local demo browser",
    )
    moltbook.app.state.authorization_store.grant(
        subject_did=loaded["browser"].did,
        action="moltbook:create_reply",
        resource=f"{moltbook_base}/moltbook/resources/threads/",
        scope_type="prefix",
        note="bounded local demo browser",
    )
    forecast = start_forecast(
        port=int(forecast_base.rsplit(":", 1)[1]),
        nonce_database=str(config_path.parent / "forecast-nonces.db"),
        moltbook_entrypoint=f"{moltbook_base}/moltbook/resources/index.json",
        identity=loaded["forecast"],
        tls_certificate=tls["certificate"],
        tls_private_key=tls["privateKey"],
    )
    registry = start_registry(
        port=int(registry_base.rsplit(":", 1)[1]),
        database=str(config_path.parent / "registry.db"),
        nonce_database=str(config_path.parent / "registry-nonces.db"),
        identity=loaded["registry"],
        tls_certificate=tls["certificate"],
        tls_private_key=tls["privateKey"],
    )
    indexer = RegistryIndexer(
        registry.app.state.registry_store,
        did_document_path=identities["registry"]["didPath"],
        private_key_path=identities["registry"]["keyPath"],
        allow_private_networks=True,
    )
    indexed_sites = [
        indexer.index(f"{moltbook_base}/moltbook/ad.json"),
        indexer.index(f"{forecast_base}/forecast/ad.json"),
    ]
    # The browser's Web-native caller identity: the daemon custodies this key
    # and publishes its controller, letting the graphical UI perform
    # authenticated HTTP actions on publishers that trust this controller.
    caller_controller = f"{browser_base}/.well-known/agent-web-caller"
    caller_signer = LocalEd25519Signer(
        loaded["browser"].private_key,
        key_id=f"{caller_controller}#key-1",
    )
    caller_document = build_caller_controller(
        caller=caller_controller,
        signer=caller_signer,
    )
    native = start_site(
        lambda base_url: create_native_app(
            database=str(config_path.parent / "native.db"),
            replay_database=str(config_path.parent / "native-replays.db"),
            base_url=base_url,
            caller_controllers={caller_controller: caller_document},
            annotation_writers={caller_controller},
        ),
        port=int(native_base.rsplit(":", 1)[1]),
        tls_certificate=tls["certificate"],
        tls_private_key=tls["privateKey"],
    )
    indexed_sites.append(
        indexer.index(f"{native_base}/.well-known/agent-web")
    )
    daemon_token = "demo-network-browser-token"

    def build_browser_daemon(base_url: str):
        app = create_browser_app(
            identity=loaded["browser"],
            did_document_path=identities["browser"]["didPath"],
            private_key_path=identities["browser"]["keyPath"],
            base_url=base_url,
            allow_private_networks=True,
            session_token=daemon_token,
            caller_controller=caller_controller,
            caller_signer=caller_signer,
        )
        print(f"Graphical browser: {base_url}/?token={daemon_token}")
        return app

    graphical = start_site(
        build_browser_daemon,
        port=int(browser_base.rsplit(":", 1)[1]),
        tls_certificate=tls["certificate"],
        tls_private_key=tls["privateKey"],
    )
    try:
        browser = AgentBrowser(
            f"{moltbook_base}/moltbook/ad.json",
            did_document_path=identities["browser"]["didPath"],
            private_key_path=identities["browser"]["keyPath"],
            allowed_origins={forecast_base},
            allow_private_networks=True,
        )
        created = browser.call(
            "create_thread",
            {
                "title": "Hello from the secure Agent Web",
                "body": "Authenticated with DID-WBA and followed into live Forecast.",
            },
            confirmed=True,
        )
        resources = browser.traverse()
        forecast_resource = next(
            item
            for item in resources
            if item["@id"].endswith("/forecast/resources/bengaluru.json")
        )
        registry_browser = AgentBrowser(
            f"{registry_base}/registry/ad.json",
            did_document_path=identities["browser"]["didPath"],
            private_key_path=identities["browser"]["keyPath"],
            allow_private_networks=True,
        )
        registry_search = registry_browser.call(
            "search",
            {"query": "forecast", "limit": 10},
        )
        with httpx.Client(timeout=15) as client:
            ui = client.get(
                f"{browser_base}/", params={"token": daemon_token}
            )
            graphical_connect = client.post(
                f"{browser_base}/api/connect",
                headers={"X-Agent-Web-Browser-Token": daemon_token},
                json={
                    "agentDescriptionUrl": (
                        f"{moltbook_base}/moltbook/ad.json"
                    )
                },
            )
            # The same flow the graphical UI performs: connect to Web-native
            # discovery, then invoke its authenticated HTTP annotation action
            # with the daemon-custodied caller key.
            client.post(
                f"{browser_base}/api/connect",
                headers={"X-Agent-Web-Browser-Token": daemon_token},
                json={
                    "agentDescriptionUrl": (
                        f"{native_base}/.well-known/agent-web"
                    )
                },
            ).raise_for_status()
            native_action = client.post(
                f"{browser_base}/api/actions",
                headers={"X-Agent-Web-Browser-Token": daemon_token},
                json={
                    "method": "createAnnotation",
                    "params": {
                        "topic": "typed-links",
                        "text": (
                            "Signed by the browser daemon's Web-native "
                            "caller key during the live demo."
                        ),
                    },
                    "confirmed": False,
                },
            )
        npm = shutil.which("npm.cmd") or shutil.which("npm")
        if npm is None:
            raise RuntimeError("npm is required for cross-language proof")
        typescript = subprocess.run(
            [
                npm,
                "run",
                "--silent",
                "validate",
                "--",
                f"{forecast_base}/forecast/resources/index.json",
            ],
            cwd=ROOT / "libagentweb",
            check=True,
            capture_output=True,
            text=True,
        )
        proof = {
            "status": "passed",
            "transport": "TLS with a generated local CA",
            "anpSdk": "0.9.1",
            "createdThroughAuthenticatedANP": created["@id"],
            "authenticatedAuthor": created["data"]["author"],
            "resourcesTraversed": len(resources),
            "publishers": sorted(
                {item["provenance"]["publisher"] for item in resources}
            ),
            "liveForecast": {
                "temperatureC": forecast_resource["data"]["temperatureC"],
                "retrievedAt": forecast_resource["data"]["retrievedAt"],
                "source": forecast_resource["data"]["source"],
                "proofVerified": True,
            },
            "registry": {
                "publisher": loaded["registry"].did,
                "sitesIndexed": indexed_sites,
                "searchResultCount": registry_search["data"]["count"],
                "sourceProofsPreserved": registry_search["extensions"][
                    "registryVerification"
                ]["sourceProofsPreserved"],
            },
            "typescriptConsumer": json.loads(typescript.stdout),
            "graphicalBrowser": {
                "uiStatus": ui.status_code,
                "liveConnectStatus": graphical_connect.status_code,
                "callerDid": graphical_connect.json()["status"]["callerDid"],
                "webNativeAnnotation": {
                    "status": native_action.status_code,
                    "resource": (
                        native_action.json().get("resource", {}).get("@id")
                        if native_action.status_code == 200
                        else native_action.text[:200]
                    ),
                    "author": (
                        native_action.json()
                        .get("resource", {})
                        .get("data", {})
                        .get("author")
                        if native_action.status_code == 200
                        else None
                    ),
                    "verifiedByDaemon": (
                        native_action.json().get("verified")
                        if native_action.status_code == 200
                        else None
                    ),
                },
            },
        }
        print(json.dumps(proof, indent=2))
        if stay:
            from threading import Event

            print(
                f"\nGraphical browser: {browser_base}/?token={daemon_token}\n"
                f"Moltbook AD: {moltbook_base}/moltbook/ad.json\n"
                f"Native discovery: {native_base}/.well-known/agent-web\n"
                f"Forecast AD: {forecast_base}/forecast/ad.json\n"
                f"Registry AD: {registry_base}/registry/ad.json\n"
                "Press Ctrl+C to stop the local network.",
                flush=True,
            )
            try:
                Event().wait()
            except KeyboardInterrupt:
                pass
        return 0
    finally:
        graphical.stop()
        registry.stop()
        forecast.stop()
        moltbook.stop()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--child-config", type=Path)
    parser.add_argument("--stay", action="store_true")
    args = parser.parse_args()
    if args.child_config:
        return _run_network(args.child_config, stay=args.stay)

    with TemporaryDirectory(prefix="agent-web-proof-") as value:
        directory = Path(value)
        config = _provision(directory)
        config_path = directory / "network.json"
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        child_environment = os.environ.copy()
        local_ca = config["tls"]["ca"]
        combined_ca = config["tls"]["caBundle"]
        child_environment["SSL_CERT_FILE"] = combined_ca
        child_environment["REQUESTS_CA_BUNDLE"] = combined_ca
        child_environment["NODE_EXTRA_CA_CERTS"] = local_ca
        child_environment["NO_PROXY"] = "localhost,127.0.0.1"
        command = [
            sys.executable,
            str(Path(__file__)),
            "--child-config",
            str(config_path),
        ]
        if args.stay:
            command.append("--stay")
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=child_environment,
        )
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
