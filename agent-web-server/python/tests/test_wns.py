from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from agent_web_server import (
    HandleStore,
    generate_publisher_identity,
    mount_handle_provider,
)
from anp.wns import HandleStatus
from fastapi import FastAPI
from fastapi.testclient import TestClient


class WnsProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.store = HandleStore(
            Path(self.temp.name) / "wns.sqlite3",
            provider_domain="publisher.example",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def identity(self, name: str = "moltbook"):
        return generate_publisher_identity(
            base_url="https://publisher.example",
            agent_name=name,
            agent_description_path=f"/{name}/ad.json",
            handle="moltbook.publisher.example",
        )

    def test_identity_and_provider_publish_an_exact_binding(self) -> None:
        identity = self.identity()
        self.assertEqual(identity.handle, "moltbook.publisher.example")
        binding = self.store.bind(identity.handle, identity.did)
        self.assertEqual(binding.binding_generation, "1")

        app = FastAPI()
        mount_handle_provider(app, self.store)
        response = TestClient(app).get("/.well-known/handle/moltbook")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["did"], identity.did)
        self.assertEqual(response.json()["binding_generation"], "1")
        self.assertEqual(response.headers["cache-control"], "public, max-age=300")

    def test_rotation_status_generation_and_history_fail_closed(self) -> None:
        first = self.identity()
        first_binding = self.store.bind(first.handle, first.did)
        successor = self.identity("successor")
        rotated = self.store.bind(
            first.handle,
            successor.did,
            expected_did=first.did,
        )
        self.assertEqual(rotated.binding_generation, "2")
        with self.assertRaises(ValueError):
            self.store.bind(
                first.handle,
                self.identity("attacker").did,
                expected_did=first.did,
            )

        suspended = self.store.set_status(
            first.handle,
            HandleStatus.SUSPENDED,
            expected_generation=rotated.binding_generation,
        )
        self.assertEqual(suspended.binding_generation, "3")
        revoked = self.store.set_status(
            first.handle,
            HandleStatus.REVOKED,
            expected_generation=suspended.binding_generation,
        )
        self.assertEqual(revoked.binding_generation, "4")
        with self.assertRaises(ValueError):
            self.store.set_status(
                first.handle,
                HandleStatus.ACTIVE,
                expected_generation=revoked.binding_generation,
            )
        with self.assertRaises(ValueError):
            self.store.bind(
                first.handle,
                first.did,
                expected_did=successor.did,
            )

        app = FastAPI()
        mount_handle_provider(app, self.store)
        response = TestClient(app).get("/.well-known/handle/moltbook")
        self.assertEqual(response.status_code, 410)
        self.assertEqual(len(self.store.history(first.handle)), 4)
        self.assertTrue(self.store.integrity_check())
        self.assertEqual(first_binding.status, HandleStatus.ACTIVE)

    def test_domain_and_handle_constraints_are_enforced(self) -> None:
        identity = self.identity()
        with self.assertRaises(ValueError):
            self.store.bind("moltbook.other.example", identity.did)
        with self.assertRaises(ValueError):
            generate_publisher_identity(
                base_url="https://publisher.example",
                agent_name="bad",
                agent_description_path="/bad/ad.json",
                handle="bad.other.example",
            )


if __name__ == "__main__":
    unittest.main()
