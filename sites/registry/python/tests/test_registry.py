from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from agent_web_server import generate_publisher_identity
from fastapi.testclient import TestClient
from libagentweb import (
    AGENT_WEB_VERSION,
    empty_affordances,
    sign_resource,
    verify_resource,
)
from registry_site import RegistryIndexer, RegistryStore, create_app


def _time(offset: int = 0) -> str:
    return (
        datetime.now(timezone.utc) + timedelta(seconds=offset)
    ).isoformat().replace("+00:00", "Z")


class RegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        root = Path(self.temp.name)
        self.source = generate_publisher_identity(
            base_url="https://source.example",
            agent_name="source",
            agent_description_path="/source/ad.json",
        )
        self.registry = generate_publisher_identity(
            base_url="https://testserver",
            agent_name="registry",
            agent_description_path="/registry/ad.json",
        )
        self.database = root / "registry.db"
        self.store = RegistryStore(self.database)
        description = {
            "identifier": self.source.did,
            "name": "Source Publisher",
            "proof": {"placeholder": "verified by indexer before admission"},
        }
        resource = sign_resource(
            {
                "@context": "https://source.example/agent-web/0.2/context.jsonld",
                "@id": "https://source.example/source/resources/weather.json",
                "@type": ["AgentWebResource", "WeatherForecast"],
                "agentWeb": {"version": AGENT_WEB_VERSION, "kind": "resource"},
                "name": "Bengaluru weather",
                "description": "Current verified forecast for Bengaluru.",
                "links": [
                    {
                        "rel": "self",
                        "href": (
                            "https://source.example/source/resources/weather.json"
                        ),
                    }
                ],
                "affordances": empty_affordances(),
                "provenance": {
                    "publisher": self.source.did,
                    "createdAt": _time(-10),
                    "updatedAt": _time(),
                    "canonical": (
                        "https://source.example/source/resources/weather.json"
                    ),
                },
                "data": {"temperatureC": 25},
            },
            private_key=self.source.private_key,
            publisher_did=self.source.did,
            verification_method=self.source.verification_method,
        )
        self.store.replace_verified_site(
            agent_description_url="https://source.example/source/ad.json",
            description=description,
            resources=[resource],
        )
        self.store.close()
        self.app = create_app(
            database=self.database,
            nonce_database=root / "nonces.db",
            base_url="https://testserver",
            identity=self.registry,
        )
        self.client = TestClient(self.app, base_url="https://testserver")

    def tearDown(self) -> None:
        self.client.close()
        self.app.state.close()
        self.temp.cleanup()

    def test_search_preserves_source_proof_digest_and_publisher(self) -> None:
        response = self.client.get(
            "/registry/resources/search.json",
            params={"q": "Bengaluru", "limit": 10},
        )
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        verify_resource(
            result,
            publisher_did_document=self.registry.did_document,
        )
        source = result["data"]["results"][0]["source"]
        self.assertEqual(source["publisher"], self.source.did)
        self.assertEqual(source["proof"]["verificationMethod"], self.source.verification_method)
        self.assertEqual(source["digest"]["canonicalization"], "RFC8785-JCS")
        self.assertEqual(len(source["digest"]["value"]), 64)
        self.assertTrue(
            result["extensions"]["registryVerification"][
                "registryDoesNotReplaceSourceTrust"
            ]
        )

    def test_collection_and_human_directory_share_index(self) -> None:
        collection = self.client.get(
            "/registry/resources/index.json"
        ).json()
        self.assertEqual(collection["data"]["counts"], {"sites": 1, "resources": 1})
        self.assertEqual(collection["data"]["sites"][0]["publisher"], self.source.did)
        page = self.client.get("/directory", params={"q": "forecast"})
        self.assertIn("Bengaluru weather", page.text)
        self.assertIn(self.source.did, page.text)

    def test_store_rejects_mixed_publishers_and_escapes_like_wildcards(self) -> None:
        store = self.app.state.registry_store
        self.assertEqual(store.search("%", limit=10), [])
        sites_before = store.counts()
        foreign = generate_publisher_identity(
            base_url="https://foreign.example",
            agent_name="foreign",
            agent_description_path="/foreign/ad.json",
        )
        resource = self.client.get("/registry/resources/index.json").json()
        with self.assertRaises(ValueError):
            store.replace_verified_site(
                agent_description_url="https://source.example/source/ad.json",
                description={"identifier": foreign.did, "name": "Foreign"},
                resources=[resource],
            )
        self.assertEqual(store.counts(), sites_before)


class RegistryIndexerBoundsTests(unittest.TestCase):
    def test_resource_limit_is_checked_before_fetching_the_next_link(self) -> None:
        class FakeBrowser:
            opened: list[str] = []

            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            def discover(self) -> dict:
                return {
                    "identifier": "did:wba:source.example:agents:test:e1_test"
                }

            def open_entrypoint(self) -> dict:
                return {
                    "@id": "https://source.example/resources/index.json",
                    "provenance": {
                        "publisher": (
                            "did:wba:source.example:agents:test:e1_test"
                        )
                    },
                    "links": [
                        {
                            "rel": "item",
                            "href": "https://source.example/resources/next.json",
                        }
                    ],
                }

            def open(self, url: str) -> dict:
                self.opened.append(url)
                raise AssertionError("limit check happened after network fetch")

        with TemporaryDirectory() as value:
            store = RegistryStore(Path(value) / "registry.db")
            try:
                with patch(
                    "registry_site.indexer.AgentBrowser",
                    FakeBrowser,
                ):
                    indexer = RegistryIndexer(
                        store,
                        did_document_path="did.json",
                        private_key_path="key.pem",
                        allow_private_networks=True,
                    )
                    with self.assertRaisesRegex(RuntimeError, "resource limit"):
                        indexer.index(
                            "https://source.example/source/ad.json",
                            max_resources=1,
                        )
                self.assertEqual(FakeBrowser.opened, [])
                self.assertEqual(store.counts(), {"sites": 0, "resources": 0})
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
