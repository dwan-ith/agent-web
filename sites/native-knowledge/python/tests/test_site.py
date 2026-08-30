from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient
from libagentweb import (
    LocalEd25519Signer,
    WebAgentBrowser,
    build_caller_controller,
    sign_agent_web_request,
    validate_discovery_document,
    verify_resource,
)
from native_knowledge_site import create_app


class NativeKnowledgeSiteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.caller = "https://browser.example/.well-known/agent-web-caller"
        self.signer = LocalEd25519Signer(
            ed25519.Ed25519PrivateKey.generate(),
            key_id=f"{self.caller}#key-1",
        )
        controller = build_caller_controller(caller=self.caller, signer=self.signer)
        self.app = create_app(
            database=Path(self.temp.name) / "knowledge.db",
            replay_database=Path(self.temp.name) / "replays.db",
            caller_controllers={self.caller: controller},
            annotation_writers={self.caller},
        )
        self.client = TestClient(self.app, base_url="https://native.example")

    def tearDown(self) -> None:
        self.client.close()
        self.app.state.close()
        self.temp.cleanup()

    def test_site_has_discovery_and_signed_graph_but_no_html_projection(self) -> None:
        discovery_response = self.client.get("/.well-known/agent-web")
        self.assertEqual(discovery_response.status_code, 200)
        self.assertEqual(discovery_response.headers["content-type"].split(";")[0], "application/agent-web-discovery+json")
        discovery = validate_discovery_document(
            discovery_response.json(),
            discovery_url="https://native.example/.well-known/agent-web",
        )
        self.assertNotIn("humanView", discovery["agentWeb"])

        entry_response = self.client.get("/resources/index")
        self.assertEqual(entry_response.headers["content-type"].split(";")[0], "application/agent-web+json")
        entry = verify_resource(entry_response.json(), controller_document=discovery)
        self.assertIsNone(entry["data"]["humanView"])
        self.assertFalse(entry["data"]["anpRequired"])
        self.assertGreaterEqual(len([link for link in entry["links"] if link["rel"] == "item"]), 2)
        self.assertEqual(self.client.get("/").status_code, 404)
        media_types = {
            getattr(route.response_class, "media_type", None)
            for route in self.app.routes
            if hasattr(route, "response_class")
        }
        self.assertNotIn("text/html", media_types)

    def test_typed_navigation_and_http_search_are_live(self) -> None:
        entry = self.client.get("/resources/index").json()
        topic_url = next(link["href"] for link in entry["links"] if link["rel"] == "item")
        topic = self.client.get(topic_url).json()
        self.assertEqual(topic["agentWeb"]["kind"], "resource")
        action = entry["affordances"]["actions"]["search"]
        self.assertEqual(action["interfaces"][0]["protocol"], "HTTP")
        self.assertEqual(action["input"]["properties"]["limit"]["maximum"], 100)
        result = self.client.get("/resources/search", params={"q": "typed", "limit": 20}).json()
        self.assertEqual(result["data"]["count"], 1)
        self.assertTrue(any(link["rel"] == "item" for link in result["links"]))

    def test_generic_agent_browser_opens_and_navigates_native_site(self) -> None:
        async def fetch(url: str) -> dict:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200, response.text)
            return response.json()

        async def scenario() -> None:
            browser = WebAgentBrowser(
                "https://native.example/.well-known/agent-web",
                fetch_document=fetch,
            )
            entry = await browser.open_entrypoint()
            topic_url = next(
                link["href"] for link in entry["links"] if link["rel"] == "item"
            )
            topic = await browser.open(topic_url)
            self.assertIn("KnowledgeTopic", topic["@type"])

        __import__("asyncio").run(scenario())

    def test_database_is_persistent_and_wildcards_are_literal(self) -> None:
        self.assertEqual(self.app.state.knowledge_store.search("%"), [])
        self.assertTrue(self.app.state.knowledge_store.integrity_check())

    def test_https_origin_and_authority_are_enforced(self) -> None:
        wrong_host = self.client.get(
            "/resources/index", headers={"Host": "attacker.example"}
        )
        self.assertEqual(wrong_host.status_code, 421)
        with TestClient(self.app, base_url="http://native.example") as cleartext:
            response = cleartext.get("/resources/index")
        self.assertEqual(response.status_code, 400)
        self.assertIn(
            "max-age=31536000",
            self.client.get("/resources/index").headers["strict-transport-security"],
        )

    def test_protected_annotation_is_authenticated_authorized_and_durable(self) -> None:
        body = b'{"text":"Machine-native authorship","topic":"agent-web"}'
        headers = sign_agent_web_request(
            method="POST",
            target_uri="https://native.example/actions/annotations",
            body=body,
            content_type="application/json",
            caller=self.caller,
            signer=self.signer,
        )
        created = self.client.post(
            "/actions/annotations", content=body, headers=headers
        )
        self.assertEqual(created.status_code, 201, created.text)
        resource = created.json()
        self.assertEqual(resource["data"]["author"], self.caller)
        self.assertEqual(resource["data"]["text"], "Machine-native authorship")
        stored = self.client.get(resource["@id"])
        self.assertEqual(stored.status_code, 200)
        self.assertEqual(stored.json()["@id"], resource["@id"])
        entry = self.client.get("/resources/index").json()
        self.assertEqual(entry["data"]["annotationCount"], 1)
        # Annotations are reachable through the bounded paginated collection.
        collection_link = next(
            link for link in entry["links"]
            if link["href"].endswith("/resources/annotations.json")
        )
        self.assertEqual(collection_link["rel"], "item")
        page = self.client.get("/resources/annotations.json").json()
        self.assertEqual(page["data"]["count"], 1)
        self.assertTrue(
            any(link["href"] == resource["@id"] for link in page["links"])
        )
        self.assertNotIn("next", {link["rel"] for link in page["links"]})

        replay = self.client.post(
            "/actions/annotations", content=body, headers=headers
        )
        self.assertEqual(replay.status_code, 401)
        self.assertIn("replayed", replay.text)

    def test_annotations_collection_paginates_with_next_links(self) -> None:
        store = self.app.state.knowledge_store
        for index in range(120):
            store.create_annotation(
                topic_slug="agent-web",
                author=self.caller,
                text=f"Bounded annotation number {index}",
            )
        first = self.client.get("/resources/annotations.json").json()
        self.assertEqual(first["data"]["page"], 0)
        self.assertEqual(first["data"]["count"], 50)
        self.assertEqual(first["data"]["annotationCount"], 120)
        next_links = [link for link in first["links"] if link["rel"] == "next"]
        self.assertEqual(len(next_links), 1)
        second = self.client.get(next_links[0]["href"]).json()
        self.assertEqual(second["@id"], next_links[0]["href"])
        self.assertEqual(second["data"]["page"], 1)
        prev_links = [link for link in second["links"] if link["rel"] == "prev"]
        self.assertEqual(len(prev_links), 1)
        last = self.client.get(
            "/resources/annotations.json?page=2"
        ).json()
        self.assertEqual(last["data"]["count"], 20)
        self.assertNotIn("next", {link["rel"] for link in last["links"]})

    def test_annotation_rate_limit_is_per_caller(self) -> None:
        headers = []
        bodies = []
        for index in range(30):
            body = json.dumps(
                {"text": f"Annotation {index}", "topic": "agent-web"}
            ).encode()
            bodies.append(body)
            headers.append(sign_agent_web_request(
                method="POST",
                target_uri="https://native.example/actions/annotations",
                body=body,
                content_type="application/json",
                caller=self.caller,
                signer=self.signer,
            ))
        for index in range(30):
            response = self.client.post(
                "/actions/annotations", content=bodies[index], headers=headers[index]
            )
            self.assertEqual(response.status_code, 201, response.text)
        overflow = sign_agent_web_request(
            method="POST",
            target_uri="https://native.example/actions/annotations",
            body=bodies[0],
            content_type="application/json",
            caller=self.caller,
            signer=self.signer,
        )
        limited = self.client.post(
            "/actions/annotations", content=bodies[0], headers=overflow
        )
        self.assertEqual(limited.status_code, 429)

    def test_annotation_rejects_malformed_topic_slugs(self) -> None:
        body = json.dumps(
            {"text": "Bad topic", "topic": "../escape"}
        ).encode()
        headers = sign_agent_web_request(
            method="POST",
            target_uri="https://native.example/actions/annotations",
            body=body,
            content_type="application/json",
            caller=self.caller,
            signer=self.signer,
        )
        response = self.client.post(
            "/actions/annotations", content=body, headers=headers
        )
        self.assertEqual(response.status_code, 422)
        self.assertIn("topic", response.text)

    def test_protected_annotation_denies_unsigned_and_tampered_requests(self) -> None:
        unsigned = self.client.post(
            "/actions/annotations",
            json={"topic": "agent-web", "text": "unsigned"},
        )
        self.assertEqual(unsigned.status_code, 401)
        body = b'{"text":"signed","topic":"agent-web"}'
        headers = sign_agent_web_request(
            method="POST",
            target_uri="https://native.example/actions/annotations",
            body=body,
            content_type="application/json",
            caller=self.caller,
            signer=self.signer,
        )
        tampered = self.client.post(
            "/actions/annotations",
            content=b'{"text":"tampered","topic":"agent-web"}',
            headers=headers,
        )
        self.assertEqual(tampered.status_code, 401)
        self.assertIn("Content-Digest", tampered.text)
        query_changed = self.client.post(
            "/actions/annotations?unexpected=true", content=body, headers=headers
        )
        self.assertEqual(query_changed.status_code, 401)
        self.assertIn("signature", query_changed.text.lower())


if __name__ == "__main__":
    unittest.main()
