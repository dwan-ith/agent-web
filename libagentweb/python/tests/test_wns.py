from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from agent_web_server import generate_publisher_identity, write_identity
from anp.wns import build_resolution_url
from libagentweb import AgentBrowser, HandleTrustError, resolve_exact_handle


class ExactWnsResolutionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.identity = generate_publisher_identity(
            base_url="https://publisher.example",
            agent_name="moltbook",
            agent_description_path="/moltbook/ad.json",
            handle="moltbook.publisher.example",
        )
        self.resolution = {
            "handle": "moltbook.publisher.example",
            "did": self.identity.did,
            "status": "active",
            "binding_generation": "7",
        }

    async def fetch(self, url: str):
        self.assertEqual(
            url,
            build_resolution_url("moltbook", "publisher.example"),
        )
        return deepcopy(self.resolution)

    async def resolve_did(self, did: str):
        self.assertEqual(did, self.identity.did)
        return deepcopy(self.identity.did_document)

    async def test_exact_binding_and_generation_floor_are_enforced(self) -> None:
        binding = await resolve_exact_handle(
            "wba://moltbook.publisher.example",
            minimum_binding_generation="7",
            fetch_document=self.fetch,
            did_resolver=self.resolve_did,
        )
        self.assertEqual(binding.did, self.identity.did)
        self.assertEqual(binding.binding_generation, "7")

        with self.assertRaisesRegex(HandleTrustError, "older than"):
            await resolve_exact_handle(
                "moltbook.publisher.example",
                minimum_binding_generation="8",
                fetch_document=self.fetch,
                did_resolver=self.resolve_did,
            )

    async def test_provider_wide_reverse_declaration_is_not_exact(self) -> None:
        weak_document = deepcopy(self.identity.did_document)
        service = next(
            item
            for item in weak_document["service"]
            if item["type"] == "ANPHandleService"
        )
        service["serviceEndpoint"] = "https://publisher.example/handles"

        async def weak_resolver(_did: str):
            return weak_document

        with self.assertRaisesRegex(HandleTrustError, "exact canonical"):
            await resolve_exact_handle(
                "moltbook.publisher.example",
                fetch_document=self.fetch,
                did_resolver=weak_resolver,
            )

    async def test_agent_browser_can_start_from_a_verified_handle(self) -> None:
        with TemporaryDirectory() as directory:
            did_path, key_path = write_identity(
                generate_publisher_identity(
                    base_url="https://browser.example",
                    agent_name="browser",
                    agent_description_path="/browser/ad.json",
                ),
                directory=Path(directory),
            )
            browser = await AgentBrowser.from_handle_async(
                "moltbook.publisher.example",
                did_document_path=did_path,
                private_key_path=key_path,
                fetch_document=self.fetch,
                did_resolver=self.resolve_did,
            )
        self.assertEqual(
            browser.agent_description_url,
            "https://publisher.example/moltbook/ad.json",
        )
        self.assertIsNotNone(browser.handle_binding)
        self.assertEqual(browser.handle_binding.binding_generation, "7")


if __name__ == "__main__":
    unittest.main()
