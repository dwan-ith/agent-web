from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from libagentweb import (
    DiscoveryValidationError,
    ResourceTrustError,
    WebAgentBrowser,
    build_discovery_document,
    empty_affordances,
    http_action,
    sign_resource,
)


async def _async_value(value: dict) -> dict:
    return value


class WebNativeBrowserTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.origin = "https://publisher.example"
        self.publisher = f"{self.origin}/.well-known/agent-web"
        self.entrypoint = f"{self.origin}/resources/index"
        self.key = ed25519.Ed25519PrivateKey.generate()
        public = self.key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.method = f"{self.publisher}#key-1"
        self.discovery = build_discovery_document(
            base_url=self.origin,
            entry_point=self.entrypoint,
            publisher=self.publisher,
            verification_methods=[
                {
                    "id": self.method,
                    "type": "Multikey",
                    "controller": self.publisher,
                    "publicKeyMultibase": "z"
                    + base58.b58encode(b"\xed\x01" + public).decode("ascii"),
                }
            ],
            assertion_methods=[self.method],
            name="Native publisher",
            description="An Agent Web site with no World Wide Web projection.",
        )
        now = datetime.now(timezone.utc)
        timestamp = now.isoformat().replace("+00:00", "Z")
        unsigned = {
            "@context": "urn:agent-web:context:0.2",
            "@id": self.entrypoint,
            "@type": "AgentWebCollection",
            "agentWeb": {"version": "0.2", "kind": "collection"},
            "name": "Web-native collection",
            "links": [],
            "affordances": {
                **empty_affordances(),
                "actions": {
                    "search": http_action(
                        description="Search the native site",
                        url=f"{self.origin}/resources/search",
                        method="GET",
                        input_schema={
                            "type": "object",
                            "required": ["q"],
                            "additionalProperties": False,
                            "properties": {"q": {"type": "string", "minLength": 1}},
                        },
                        output_schema={"type": "object"},
                        safe=True,
                        idempotent=True,
                        authorization_level="normal",
                    )
                },
            },
            "provenance": {
                "publisher": self.publisher,
                "createdAt": timestamp,
                "updatedAt": timestamp,
                "expiresAt": (now + timedelta(minutes=5)).isoformat().replace(
                    "+00:00", "Z"
                ),
                "canonical": self.entrypoint,
            },
            "data": {"transport": "HTTPS", "anpRequired": False},
        }
        self.resource = sign_resource(
            unsigned,
            private_key=self.key,
            publisher=self.publisher,
            verification_method=self.method,
        )

    async def test_discovers_and_verifies_without_anp(self) -> None:
        documents = {
            f"{self.origin}/.well-known/agent-web": self.discovery,
            self.entrypoint: self.resource,
        }

        async def fetch(url: str) -> dict:
            return documents[url]

        browser = WebAgentBrowser(
            f"{self.origin}/.well-known/agent-web",
            fetch_document=fetch,
        )
        opened = await browser.open_entrypoint()
        self.assertFalse(opened["data"]["anpRequired"])
        self.assertEqual(opened["provenance"]["publisher"], self.publisher)
        self.assertNotIn("humanView", self.discovery["agentWeb"])
        self.assertEqual(self.discovery["name"], "Native publisher")

    async def test_tampered_web_resource_is_rejected(self) -> None:
        tampered = {**self.resource, "data": {"transport": "forged"}}

        async def fetch(url: str) -> dict:
            if url.endswith("/.well-known/agent-web"):
                return self.discovery
            return tampered

        browser = WebAgentBrowser(
            f"{self.origin}/.well-known/agent-web",
            fetch_document=fetch,
        )
        with self.assertRaises(ResourceTrustError):
            await browser.open_entrypoint()

    async def test_invokes_verified_http_action_without_anp(self) -> None:
        result_url = f"{self.origin}/resources/search?q=links"
        result = sign_resource(
            {
                **{key: value for key, value in self.resource.items() if key != "proof"},
                "@id": result_url,
                "name": "Search results",
                "links": [{"rel": "self", "href": result_url}],
                "affordances": empty_affordances(),
                "provenance": {
                    **self.resource["provenance"],
                    "canonical": result_url,
                },
                "data": {"query": "links", "count": 1},
            },
            private_key=self.key,
            publisher=self.publisher,
            verification_method=self.method,
        )
        calls: list[tuple[str, str, dict]] = []

        async def fetch(url: str) -> dict:
            if url.endswith("/.well-known/agent-web"):
                return self.discovery
            return self.resource

        async def action_fetch(method: str, url: str, params: dict) -> dict:
            calls.append((method, url, params))
            return result

        browser = WebAgentBrowser(
            f"{self.origin}/.well-known/agent-web",
            fetch_document=fetch,
            fetch_action=action_fetch,
        )
        await browser.open_entrypoint()
        opened = await browser.invoke("search", {"q": "links"})
        self.assertEqual(opened["data"]["count"], 1)
        self.assertEqual(
            calls,
            [("GET", f"{self.origin}/resources/search", {"q": "links"})],
        )

    async def test_http_action_input_and_origin_are_enforced(self) -> None:
        browser = WebAgentBrowser(
            f"{self.origin}/.well-known/agent-web",
            fetch_document=lambda url: _async_value(
                self.discovery if url.endswith("/.well-known/agent-web") else self.resource
            ),
        )
        await browser.open_entrypoint()
        with self.assertRaisesRegex(ValueError, "action input"):
            await browser.invoke("search", {})

    def test_discovery_rejects_cross_origin_entrypoint(self) -> None:
        with self.assertRaises(DiscoveryValidationError):
            build_discovery_document(
                base_url=self.origin,
                entry_point="https://attacker.example/resources",
                publisher=self.publisher,
                verification_methods=self.discovery["verificationMethod"],
                assertion_methods=[self.method],
            )

    def test_http_is_the_native_action_binding(self) -> None:
        action = http_action(
            description="Read the collection",
            url=self.entrypoint,
            method="GET",
            input_schema={"type": "object", "additionalProperties": False},
            output_schema={"type": "object"},
            safe=True,
            idempotent=True,
            authorization_level="normal",
        )
        self.assertEqual(action["interfaces"][0]["protocol"], "HTTP")
        with self.assertRaisesRegex(ValueError, "safe HTTP"):
            http_action(
                description="Invalid safe mutation",
                url=self.entrypoint,
                method="POST",
                input_schema={},
                output_schema={},
                safe=True,
                idempotent=False,
                authorization_level="normal",
            )


if __name__ == "__main__":
    unittest.main()
