from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import ssl
from tempfile import TemporaryDirectory
import unittest

from agent_web_browser import create_app as create_browser_app
from agent_web_server import (
    find_free_port,
    generate_local_tls,
    generate_publisher_identity,
    start_site,
    write_identity,
)
from forecast_site import StaticForecastProvider, start_forecast
import httpx
from libagentweb import ActionConfirmationRequired, AgentBrowser
from moltbook_site import start_moltbook
from registry_site import RegistryIndexer, start_registry


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


class SecureAgentWebNetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = TemporaryDirectory()
        root = Path(cls.temp.name)
        cls.tls = generate_local_tls(root / "tls")
        cls.previous_environment = {
            name: os.environ.get(name)
            for name in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NO_PROXY")
        }
        os.environ["SSL_CERT_FILE"] = str(cls.tls.ca_certificate)
        os.environ["REQUESTS_CA_BUNDLE"] = str(cls.tls.ca_certificate)
        os.environ["NO_PROXY"] = "localhost,127.0.0.1"
        # aiohttp snapshots its default SSL context when imported. This test
        # generates its CA at runtime, so refresh that cached context before
        # exercising the official ANP client and verifier.
        import aiohttp.connector

        aiohttp.connector._SSL_CONTEXT_VERIFIED = ssl.create_default_context(
            cafile=str(cls.tls.ca_certificate)
        )

        ports: list[int] = []
        while len(ports) < 4:
            port = find_free_port()
            if port not in ports:
                ports.append(port)
        moltbook_port, forecast_port, registry_port, browser_port = ports
        cls.moltbook_base = f"https://localhost:{moltbook_port}"
        cls.forecast_base = f"https://localhost:{forecast_port}"
        cls.browser_base = f"https://localhost:{browser_port}"
        cls.registry_base = f"https://localhost:{registry_port}"
        cls.moltbook_identity = generate_publisher_identity(
            base_url=cls.moltbook_base,
            agent_name="moltbook",
            agent_description_path="/moltbook/ad.json",
        )
        cls.forecast_identity = generate_publisher_identity(
            base_url=cls.forecast_base,
            agent_name="forecast",
            agent_description_path="/forecast/ad.json",
        )
        cls.browser_identity = generate_publisher_identity(
            base_url=cls.browser_base,
            agent_name="browser",
            agent_description_path="/browser/ad.json",
        )
        cls.registry_identity = generate_publisher_identity(
            base_url=cls.registry_base,
            agent_name="registry",
            agent_description_path="/registry/ad.json",
        )
        cls.browser_did_path, cls.browser_key_path = write_identity(
            cls.browser_identity,
            directory=root / "browser-identity",
        )
        cls.registry_did_path, cls.registry_key_path = write_identity(
            cls.registry_identity,
            directory=root / "registry-identity",
        )

        now = datetime.now(timezone.utc)
        records = {}
        for slug, name, temperature in (
            ("bengaluru", "Bengaluru", 24.5),
            ("geneva", "Geneva", 20.0),
            ("nairobi", "Nairobi", 22.0),
        ):
            records[slug] = {
                "slug": slug,
                "location": name,
                "temperatureC": temperature,
                "condition": "Test conditions from an injected provider",
                "observedAt": _timestamp(now),
                "retrievedAt": _timestamp(now),
                "validThrough": _timestamp(now + timedelta(minutes=5)),
                "source": f"https://api.open-meteo.com/acceptance/{slug}",
                "sourceProvider": "Open-Meteo",
            }

        cls.moltbook = start_moltbook(
            port=moltbook_port,
            database=str(root / "moltbook.db"),
            nonce_database=str(root / "moltbook-nonces.db"),
            authorization_database=str(root / "moltbook-authorization.db"),
            seed=False,
            forecast_entrypoint=(
                f"{cls.forecast_base}/forecast/resources/index.json"
            ),
            identity=cls.moltbook_identity,
            tls_certificate=str(cls.tls.certificate),
            tls_private_key=str(cls.tls.private_key),
        )
        cls.moltbook.app.state.authorization_store.grant(
            subject_did=cls.browser_identity.did,
            action="moltbook:create_thread",
            resource=f"{cls.moltbook_base}/moltbook/resources/index.json",
            note="acceptance browser",
        )
        cls.moltbook.app.state.authorization_store.grant(
            subject_did=cls.browser_identity.did,
            action="moltbook:create_reply",
            resource=f"{cls.moltbook_base}/moltbook/resources/threads/",
            scope_type="prefix",
            note="acceptance browser",
        )
        cls.forecast = start_forecast(
            port=forecast_port,
            nonce_database=str(root / "forecast-nonces.db"),
            moltbook_entrypoint=(
                f"{cls.moltbook_base}/moltbook/resources/index.json"
            ),
            provider=StaticForecastProvider(records),
            identity=cls.forecast_identity,
            tls_certificate=str(cls.tls.certificate),
            tls_private_key=str(cls.tls.private_key),
        )
        cls.registry = start_registry(
            port=registry_port,
            database=str(root / "registry.db"),
            nonce_database=str(root / "registry-nonces.db"),
            identity=cls.registry_identity,
            tls_certificate=str(cls.tls.certificate),
            tls_private_key=str(cls.tls.private_key),
        )
        indexer = RegistryIndexer(
            cls.registry.app.state.registry_store,
            did_document_path=cls.registry_did_path,
            private_key_path=cls.registry_key_path,
            allow_private_networks=True,
        )
        cls.moltbook_index_result = indexer.index(
            f"{cls.moltbook_base}/moltbook/ad.json"
        )
        cls.forecast_index_result = indexer.index(
            f"{cls.forecast_base}/forecast/ad.json"
        )
        cls.graphical = start_site(
            lambda base_url: create_browser_app(
                identity=cls.browser_identity,
                did_document_path=cls.browser_did_path,
                private_key_path=cls.browser_key_path,
                base_url=base_url,
                allow_private_networks=True,
            ),
            port=browser_port,
            tls_certificate=str(cls.tls.certificate),
            tls_private_key=str(cls.tls.private_key),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.graphical.stop()
        cls.registry.stop()
        cls.forecast.stop()
        cls.moltbook.stop()
        for name, value in cls.previous_environment.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        cls.temp.cleanup()

    def browser(self) -> AgentBrowser:
        return AgentBrowser(
            f"{self.moltbook_base}/moltbook/ad.json",
            did_document_path=self.browser_did_path,
            private_key_path=self.browser_key_path,
            allowed_origins={self.forecast_base},
            allow_private_networks=True,
        )

    def test_official_anp_authentication_confirmation_and_caller_authorship(self) -> None:
        browser = self.browser()
        description = browser.discover()
        self.assertEqual(description["identifier"], self.moltbook_identity.did)
        with self.assertRaises(ActionConfirmationRequired):
            browser.call(
                "create_thread",
                {"title": "No confirmation", "body": "Must not execute."},
            )
        created = browser.call(
            "create_thread",
            {
                "title": "Secure live traversal",
                "body": "Created over TLS and DID-WBA HTTP signatures.",
            },
            confirmed=True,
        )
        self.assertEqual(created["data"]["author"], self.browser_identity.did)
        self.assertEqual(
            created["provenance"]["publisher"],
            self.moltbook_identity.did,
        )

    def test_one_browser_verifies_and_traverses_two_publishers(self) -> None:
        resources = self.browser().traverse()
        publishers = {item["provenance"]["publisher"] for item in resources}
        self.assertEqual(
            publishers,
            {self.moltbook_identity.did, self.forecast_identity.did},
        )
        self.assertIn(
            f"{self.forecast_base}/forecast/resources/geneva.json",
            {item["@id"] for item in resources},
        )
        self.assertGreaterEqual(len(resources), 5)

    def test_safe_forecast_action_still_uses_authenticated_anp(self) -> None:
        browser = AgentBrowser(
            f"{self.forecast_base}/forecast/ad.json",
            did_document_path=self.browser_did_path,
            private_key_path=self.browser_key_path,
            allow_private_networks=True,
        )
        forecast = browser.call(
            "get_forecast",
            {"location": "bengaluru"},
        )
        self.assertEqual(forecast["data"]["location"], "Bengaluru")
        self.assertEqual(
            forecast["provenance"]["publisher"],
            self.forecast_identity.did,
        )

    def test_registry_indexes_only_verified_sources_and_preserves_provenance(self) -> None:
        self.assertEqual(self.moltbook_index_result["resourcesIndexed"], 1)
        self.assertEqual(self.forecast_index_result["resourcesIndexed"], 4)
        browser = AgentBrowser(
            f"{self.registry_base}/registry/ad.json",
            did_document_path=self.browser_did_path,
            private_key_path=self.browser_key_path,
            allow_private_networks=True,
        )
        result = browser.call(
            "search",
            {"query": "Geneva", "limit": 10},
        )
        self.assertEqual(
            result["provenance"]["publisher"],
            self.registry_identity.did,
        )
        self.assertGreaterEqual(result["data"]["count"], 1)
        source = result["data"]["results"][0]["source"]
        self.assertEqual(source["publisher"], self.forecast_identity.did)
        self.assertTrue(source["resource"].startswith(self.forecast_base))
        self.assertEqual(source["digest"]["canonicalization"], "RFC8785-JCS")
        self.assertIn("verificationMethod", source["proof"])

    def test_graphical_daemon_performs_live_discovery_open_and_action(self) -> None:
        with httpx.Client(
            verify=ssl.create_default_context(
                cafile=str(self.tls.ca_certificate)
            ),
            timeout=15,
        ) as client:
            page = client.get(f"{self.browser_base}/")
            self.assertEqual(page.status_code, 200)
            self.assertIn("Agent Web Browser", page.text)
            connected = client.post(
                f"{self.browser_base}/api/connect",
                json={
                    "agentDescriptionUrl": (
                        f"{self.moltbook_base}/moltbook/ad.json"
                    )
                },
            )
            self.assertEqual(connected.status_code, 200, connected.text)
            body = connected.json()
            self.assertTrue(body["entry"]["verified"])
            self.assertEqual(
                body["status"]["callerDid"],
                self.browser_identity.did,
            )
            action = client.post(
                f"{self.browser_base}/api/actions",
                json={
                    "method": "create_thread",
                    "params": {
                        "title": "Graphical browser action",
                        "body": "Executed by the real daemon, not a UI mock.",
                    },
                    "confirmed": True,
                },
            )
            self.assertEqual(action.status_code, 200, action.text)
            self.assertEqual(
                action.json()["resource"]["data"]["author"],
                self.browser_identity.did,
            )


if __name__ == "__main__":
    unittest.main()
