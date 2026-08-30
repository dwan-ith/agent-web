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

    async def test_malformed_advertised_input_schema_is_a_value_error(self) -> None:
        broken = {
            **{key: value for key, value in self.resource.items() if key != "proof"},
            "affordances": {
                **empty_affordances(),
                "actions": {
                    "search": http_action(
                        description="Search with a corrupt schema",
                        url=f"{self.origin}/resources/search",
                        method="GET",
                        input_schema={"type": "object", "required": "q"},
                        output_schema={"type": "object"},
                        safe=True,
                        idempotent=True,
                        authorization_level="normal",
                    )
                },
            },
        }
        broken = sign_resource(
            {**broken, "provenance": {**self.resource["provenance"]}},
            private_key=self.key,
            publisher=self.publisher,
            verification_method=self.method,
        )

        async def fetch(url: str) -> dict:
            if url.endswith("/.well-known/agent-web"):
                return self.discovery
            return broken

        browser = WebAgentBrowser(
            f"{self.origin}/.well-known/agent-web",
            fetch_document=fetch,
        )
        await browser.open_entrypoint()
        with self.assertRaisesRegex(ValueError, "invalid input schema"):
            await browser.invoke("search", {"q": "links"})

    async def test_cross_origin_action_verifies_against_serving_origin(self) -> None:
        # A second origin serves the action and signs the result with its own
        # discovery-authorized key.
        other_origin = "https://actions.example"
        other_publisher = f"{other_origin}/.well-known/agent-web"
        other_key = ed25519.Ed25519PrivateKey.generate()
        other_public = other_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        other_method = f"{other_publisher}#key-1"
        other_discovery = build_discovery_document(
            base_url=other_origin,
            entry_point=f"{other_origin}/resources/index",
            publisher=other_publisher,
            verification_methods=[
                {
                    "id": other_method,
                    "type": "Multikey",
                    "controller": other_publisher,
                    "publicKeyMultibase": "z"
                    + base58.b58encode(b"\xed\x01" + other_public).decode("ascii"),
                }
            ],
            assertion_methods=[other_method],
        )
        action_url = f"{other_origin}/actions/create"
        result_id = f"{other_origin}/resources/created"
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        result = sign_resource(
            {
                "@context": "urn:agent-web:context:0.2",
                "@id": result_id,
                "@type": "AgentWebResource",
                "agentWeb": {"version": "0.2", "kind": "resource"},
                "name": "Created elsewhere",
                "links": [],
                "affordances": empty_affordances(),
                "provenance": {
                    "publisher": other_publisher,
                    "createdAt": timestamp,
                    "updatedAt": timestamp,
                    "canonical": result_id,
                },
                "data": {"created": True},
            },
            private_key=other_key,
            publisher=other_publisher,
            verification_method=other_method,
        )
        advertised = sign_resource(
            {
                **{k: v for k, v in self.resource.items() if k != "proof"},
                "affordances": {
                    **empty_affordances(),
                    "actions": {
                        "create": http_action(
                            description="Create on the actions origin",
                            url=action_url,
                            method="POST",
                            input_schema={"type": "object"},
                            output_schema={"type": "object"},
                            safe=False,
                            idempotent=False,
                            authorization_level="normal",
                        )
                    },
                },
            },
            private_key=self.key,
            publisher=self.publisher,
            verification_method=self.method,
        )

        async def fetch(url: str) -> dict:
            if url.endswith("/.well-known/agent-web"):
                return (
                    self.discovery
                    if url.startswith(self.origin)
                    else other_discovery
                )
            return advertised

        async def action_fetch(method: str, url: str, params: dict) -> dict:
            return result

        browser = WebAgentBrowser(
            f"{self.origin}/.well-known/agent-web",
            allowed_origins={other_origin},
            fetch_document=fetch,
            fetch_action=action_fetch,
        )
        await browser.open_entrypoint()
        opened = await browser.invoke("create", {}, resource_url=None)
        self.assertEqual(opened["provenance"]["publisher"], other_publisher)

    async def test_cross_origin_action_rejects_foreign_publisher(self) -> None:
        # The serving origin is different, but the response claims the first
        # site's publisher; that must fail against the serving origin's
        # own discovery document.
        other_origin = "https://actions.example"
        other_discovery = build_discovery_document(
            base_url=other_origin,
            entry_point=f"{other_origin}/resources/index",
            publisher=f"{other_origin}/.well-known/agent-web",
            verification_methods=[
                {
                    "id": f"{other_origin}/.well-known/agent-web#key-1",
                    "type": "Multikey",
                    "controller": f"{other_origin}/.well-known/agent-web",
                    "publicKeyMultibase": self.discovery[
                        "verificationMethod"
                    ][0]["publicKeyMultibase"],
                }
            ],
            assertion_methods=[f"{other_origin}/.well-known/agent-web#key-1"],
        )
        action_url = f"{other_origin}/actions/create"
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        forged = sign_resource(
            {
                "@context": "urn:agent-web:context:0.2",
                "@id": f"{other_origin}/resources/created",
                "@type": "AgentWebResource",
                "agentWeb": {"version": "0.2", "kind": "resource"},
                "name": "Forged attribution",
                "links": [],
                "affordances": empty_affordances(),
                "provenance": {
                    "publisher": self.publisher,
                    "createdAt": timestamp,
                    "updatedAt": timestamp,
                    "canonical": f"{other_origin}/resources/created",
                },
                "data": {},
            },
            private_key=self.key,
            publisher=self.publisher,
            verification_method=self.method,
        )
        advertised = sign_resource(
            {
                **{k: v for k, v in self.resource.items() if k != "proof"},
                "affordances": {
                    **empty_affordances(),
                    "actions": {
                        "create": http_action(
                            description="Create on the actions origin",
                            url=action_url,
                            method="POST",
                            input_schema={"type": "object"},
                            output_schema={"type": "object"},
                            safe=False,
                            idempotent=False,
                            authorization_level="normal",
                        )
                    },
                },
            },
            private_key=self.key,
            publisher=self.publisher,
            verification_method=self.method,
        )

        async def fetch(url: str) -> dict:
            if url.endswith("/.well-known/agent-web"):
                return (
                    self.discovery
                    if url.startswith(self.origin)
                    else other_discovery
                )
            return advertised

        async def action_fetch(method: str, url: str, params: dict) -> dict:
            return forged

        browser = WebAgentBrowser(
            f"{self.origin}/.well-known/agent-web",
            allowed_origins={other_origin},
            fetch_document=fetch,
            fetch_action=action_fetch,
        )
        await browser.open_entrypoint()
        with self.assertRaisesRegex(
            ResourceTrustError, "differs from its serving origin"
        ):
            await browser.invoke("create", {})

    async def test_action_result_on_another_origin_is_rejected(self) -> None:
        # The action runs on this site but claims its result lives on another
        # origin; the identity/transport binding forbids that.
        action_url = f"{self.origin}/actions/create"
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        smuggled = sign_resource(
            {
                "@context": "urn:agent-web:context:0.2",
                "@id": "https://attacker.example/resources/stolen",
                "@type": "AgentWebResource",
                "agentWeb": {"version": "0.2", "kind": "resource"},
                "name": "Cross-origin identity",
                "links": [],
                "affordances": empty_affordances(),
                "provenance": {
                    "publisher": self.publisher,
                    "createdAt": timestamp,
                    "updatedAt": timestamp,
                    "canonical": "https://attacker.example/resources/stolen",
                },
                "data": {},
            },
            private_key=self.key,
            publisher=self.publisher,
            verification_method=self.method,
        )
        advertised = sign_resource(
            {
                **{k: v for k, v in self.resource.items() if k != "proof"},
                "affordances": {
                    **empty_affordances(),
                    "actions": {
                        "create": http_action(
                            description="Create locally",
                            url=action_url,
                            method="POST",
                            input_schema={"type": "object"},
                            output_schema={"type": "object"},
                            safe=False,
                            idempotent=False,
                            authorization_level="normal",
                        )
                    },
                },
            },
            private_key=self.key,
            publisher=self.publisher,
            verification_method=self.method,
        )

        async def fetch(url: str) -> dict:
            if url.endswith("/.well-known/agent-web"):
                return self.discovery
            return advertised

        async def action_fetch(method: str, url: str, params: dict) -> dict:
            return smuggled

        browser = WebAgentBrowser(
            f"{self.origin}/.well-known/agent-web",
            fetch_document=fetch,
            fetch_action=action_fetch,
        )
        await browser.open_entrypoint()
        with self.assertRaisesRegex(
            ResourceTrustError, "does not use the action's origin"
        ):
            await browser.invoke("create", {})

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
