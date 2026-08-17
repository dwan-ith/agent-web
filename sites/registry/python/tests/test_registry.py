from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from agent_web_server import generate_publisher_identity
from fastapi.testclient import TestClient
from libagentweb import (
    AGENT_WEB_VERSION,
    empty_affordances,
    sign_resource,
    verify_resource,
)
from registry_site import RegistryFederator, RegistryIndexer, RegistryStore, create_app


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
        self.assertEqual(source["discoveryUrl"], "https://source.example/source/ad.json")

    def test_collection_and_human_directory_share_index(self) -> None:
        collection = self.client.get(
            "/registry/resources/index.json"
        ).json()
        self.assertEqual(collection["data"]["counts"], {"sites": 1, "resources": 1})
        self.assertEqual(collection["data"]["sites"][0]["publisher"], self.source.did)
        page = self.client.get("/directory", params={"q": "forecast"})
        self.assertIn("Bengaluru weather", page.text)
        self.assertIn(self.source.did, page.text)

    def test_signed_federation_feed_contains_only_web_native_hints(self) -> None:
        store = self.app.state.registry_store
        native_identity = generate_publisher_identity(
            base_url="https://native.example",
            agent_name="native",
            agent_description_path="/native/ad.json",
        )
        publisher = "https://native.example/.well-known/agent-web"
        resource = sign_resource(
            {
                "@context": "urn:agent-web:context:0.2",
                "@id": "https://native.example/resources/index",
                "@type": ["AgentWebCollection", "NativeSite"],
                "agentWeb": {"version": AGENT_WEB_VERSION, "kind": "collection"},
                "name": "Native source",
                "description": "Web-native source",
                "links": [{"rel": "self", "href": "https://native.example/resources/index"}],
                "affordances": empty_affordances(),
                "provenance": {
                    "publisher": publisher,
                    "createdAt": _time(),
                    "updatedAt": _time(),
                    "canonical": "https://native.example/resources/index",
                },
                "data": {},
            },
            private_key=native_identity.private_key,
            publisher=publisher,
            verification_method=f"{publisher}#key-1",
        )
        store.replace_verified_site(
            discovery_url=publisher,
            description={"publisher": publisher, "name": "Native source"},
            resources=[resource],
        )
        response = self.client.get("/registry/resources/federation.json")
        self.assertEqual(response.status_code, 200, response.text)
        feed = verify_resource(
            response.json(), controller_document=self.registry.did_document
        )
        sources = [link for link in feed["links"] if link["rel"] == "source"]
        self.assertEqual([link["href"] for link in sources], [publisher])
        self.assertFalse(feed["data"]["transitiveTrust"])
        self.assertFalse(feed["extensions"]["registryFederation"]["containsAssertions"])

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
    def test_registry_core_imports_when_anp_is_unavailable(self) -> None:
        source = Path(__file__).resolve().parents[1] / "src"
        script = """
import importlib.abc
import sys
class BlockANP(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'anp' or fullname.startswith('anp.'):
            raise ModuleNotFoundError('ANP deliberately unavailable')
        return None
sys.meta_path.insert(0, BlockANP())
from registry_site import RegistryIndexer, RegistryStore
assert RegistryIndexer and RegistryStore
assert not any(name == 'anp' or name.startswith('anp.') for name in sys.modules)
"""
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(source) + os.pathsep + environment.get(
            "PYTHONPATH", ""
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

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
                indexer = RegistryIndexer(
                    store,
                    did_document_path="did.json",
                    private_key_path="key.pem",
                    allow_private_networks=True,
                    anp_browser_factory=FakeBrowser,
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


class RegistryFederationTests(unittest.TestCase):
    def _feed(self, sources: list[str], **data: object) -> dict:
        links = [
            {
                "rel": "source",
                "href": source,
                "mediaType": "application/agent-web-discovery+json",
            }
            for source in sources
        ]
        return {
            "@id": "https://peer.example/registry/resources/federation.json",
            "@type": ["AgentWebCollection", "RegistrySourceFeed"],
            "links": links,
            "data": {
                "sourceCount": len(sources),
                "transitiveTrust": False,
                **data,
            },
            "extensions": {
                "registryFederation": {
                    "profile": "urn:agent-web:registry-federation:0.1",
                    "containsAssertions": False,
                }
            },
        }

    def _federator(self, feed: dict, index_results: dict[str, object]):
        class PeerBrowser:
            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            async def discover(self) -> dict:
                return {"publisher": "https://peer.example/.well-known/agent-web"}

            async def open_entrypoint(self) -> dict:
                return {
                    "links": [{
                        "rel": "registry-federation",
                        "href": "https://peer.example/registry/resources/federation.json",
                        "mediaType": "application/agent-web+json",
                    }]
                }

            async def open(self, url: str) -> dict:
                if url != "https://peer.example/registry/resources/federation.json":
                    raise AssertionError(url)
                return feed

        class Indexer:
            calls: list[tuple[str, int]] = []

            def index(self, url: str, *, max_resources: int) -> dict:
                self.calls.append((url, max_resources))
                result = index_results[url]
                if isinstance(result, Exception):
                    raise result
                return result

        indexer = Indexer()
        return RegistryFederator(indexer, browser_factory=PeerBrowser), indexer

    def test_peer_hints_are_reindexed_from_original_sources(self) -> None:
        sources = [
            "https://one.example/.well-known/agent-web",
            "https://two.example/.well-known/agent-web",
        ]
        federator, indexer = self._federator(
            self._feed(sources),
            {
                sources[0]: {"resourcesIndexed": 3},
                sources[1]: ValueError("source proof failed"),
            },
        )
        result = federator.sync(
            "https://peer.example/.well-known/agent-web",
            max_resources_per_source=7,
        )
        self.assertEqual(indexer.calls, [(sources[0], 7), (sources[1], 7)])
        self.assertEqual(result["sourcesIndexed"], 1)
        self.assertEqual(result["resourcesIndexed"], 3)
        self.assertEqual(result["failures"][0]["discoveryUrl"], sources[1])
        self.assertEqual(result["trust"], "independent-source-reverification")

    def test_malformed_or_transitive_feeds_fail_before_indexing(self) -> None:
        valid = "https://one.example/.well-known/agent-web"
        cases = (
            self._feed([valid, valid]),
            self._feed([valid, "https://ONE.example:443/.well-known/agent-web"]),
            self._feed(["https://one.example/source/ad.json"]),
            self._feed(["https://peer.example/.well-known/agent-web"]),
            self._feed([valid], sourceCount=2),
            {
                **self._feed([valid]),
                "data": {"sourceCount": 1, "transitiveTrust": True},
            },
        )
        for feed in cases:
            with self.subTest(feed=feed):
                federator, indexer = self._federator(
                    feed, {valid: {"resourcesIndexed": 1}}
                )
                with self.assertRaises((ValueError, RuntimeError)):
                    federator.sync("https://peer.example/.well-known/agent-web")
                self.assertEqual(indexer.calls, [])

    def test_source_limit_is_enforced_before_indexing(self) -> None:
        sources = [
            f"https://source-{index}.example/.well-known/agent-web"
            for index in range(2)
        ]
        federator, indexer = self._federator(
            self._feed(sources),
            {source: {"resourcesIndexed": 1} for source in sources},
        )
        with self.assertRaisesRegex(RuntimeError, "source limit"):
            federator.sync(
                "https://peer.example/.well-known/agent-web", max_sources=1
            )
        self.assertEqual(indexer.calls, [])

    def test_agent_only_site_is_indexed_without_anp_or_html(self) -> None:
        publisher = "https://native.example/.well-known/agent-web"
        entry_url = "https://native.example/resources/index"
        timestamp = _time()
        identity = generate_publisher_identity(
            base_url="https://native.example",
            agent_name="native",
            agent_description_path="/native/ad.json",
        )
        resource = sign_resource(
            {
                "@context": "urn:agent-web:context:0.2",
                "@id": entry_url,
                "@type": ["AgentWebCollection", "NativeAgentSite"],
                "agentWeb": {"version": AGENT_WEB_VERSION, "kind": "collection"},
                "name": "Agent-only knowledge site",
                "description": "Published for agent browsers without an HTML view.",
                "links": [{"rel": "self", "href": entry_url}],
                "affordances": empty_affordances(),
                "provenance": {
                    "publisher": publisher,
                    "createdAt": timestamp,
                    "updatedAt": timestamp,
                    "canonical": entry_url,
                },
                "data": {"audience": "agents", "humanView": False},
            },
            private_key=identity.private_key,
            publisher=publisher,
            verification_method=f"{publisher}#key-1",
        )

        class FakeWebBrowser:
            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            async def discover(self) -> dict:
                return {
                    "id": publisher,
                    "publisher": publisher,
                    "name": "Agent-only knowledge site",
                    "description": "No World Wide Web projection.",
                    "agentWeb": {
                        "version": AGENT_WEB_VERSION,
                        "entryPoint": entry_url,
                    },
                }

            async def open_entrypoint(self) -> dict:
                return resource

            async def open(self, url: str) -> dict:
                raise AssertionError(f"unexpected fetch: {url}")

        with TemporaryDirectory() as value:
            store = RegistryStore(Path(value) / "registry.db")
            try:
                result = RegistryIndexer(
                    store,
                    web_browser_factory=FakeWebBrowser,
                ).index(publisher)
                self.assertEqual(result["binding"], "Agent Web")
                self.assertEqual(result["resourcesIndexed"], 1)
                site = store.sites()[0]
                self.assertEqual(site["discoveryUrl"], publisher)
                self.assertNotIn("agentDescription", site)
                self.assertEqual(store.search("knowledge")[0]["source"]["publisher"], publisher)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
