from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from agent_web_server import generate_publisher_identity
from fastapi.testclient import TestClient
from moltbook_site import create_app


class MoltbookWnsIntegrationTests(unittest.TestCase):
    def test_site_exposes_public_handle_from_its_canonical_identity(self) -> None:
        with TemporaryDirectory() as directory:
            identity = generate_publisher_identity(
                base_url="https://publisher.example",
                agent_name="moltbook",
                agent_description_path="/moltbook/ad.json",
                handle="moltbook.publisher.example",
            )
            app = create_app(
                base_url="https://publisher.example",
                identity=identity,
                database=Path(directory) / "content.db",
                nonce_database=Path(directory) / "nonces.db",
                authorization_database=Path(directory) / "authorization.db",
                handle_database=Path(directory) / "wns.db",
            )
            try:
                response = TestClient(
                    app,
                    base_url="https://publisher.example",
                ).get("/.well-known/handle/moltbook")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["did"], identity.did)
                self.assertEqual(response.json()["status"], "active")
            finally:
                app.state.close()


if __name__ == "__main__":
    unittest.main()
