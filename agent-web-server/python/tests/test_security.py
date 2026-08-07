from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import AsyncMock, patch

from agent_web_server import (
    SecurityConfig,
    generate_publisher_identity,
    install_security,
    write_identity,
)
from anp.authentication import DIDWbaAuthHeader
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient


class SecureBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        temp = Path(self.temp.name)
        self.publisher = generate_publisher_identity(
            base_url="https://testserver",
            agent_name="service",
            agent_description_path="/service/ad.json",
        )
        self.caller = generate_publisher_identity(
            base_url="https://caller.test",
            agent_name="browser",
            agent_description_path="/browser/ad.json",
        )
        did_path, key_path = write_identity(
            self.caller,
            directory=temp / "caller",
        )
        self.auth = DIDWbaAuthHeader(str(did_path), str(key_path))
        app = FastAPI()

        @app.get("/health")
        async def health() -> dict[str, str]:
            return {"status": "ok"}

        @app.post("/service/rpc")
        async def rpc(request: Request) -> dict[str, str]:
            return {"caller": request.state.did}

        self.nonces = install_security(
            app,
            SecurityConfig(
                identity=self.publisher,
                base_url="https://testserver",
                nonce_database=temp / "nonces.db",
            ),
        )
        self.client = TestClient(app, base_url="https://testserver")

    def tearDown(self) -> None:
        self.client.close()
        self.nonces.close()
        self.temp.cleanup()

    def _signed_request(self, payload: bytes) -> dict[str, str]:
        base_headers = {"Content-Type": "application/json"}
        signed = self.auth.get_auth_header(
            "https://testserver/service/rpc",
            force_new=True,
            method="POST",
            headers=base_headers,
            body=payload,
        )
        return {**base_headers, **signed}

    def test_public_get_is_hardened_but_rpc_requires_authentication(self) -> None:
        public = self.client.get("/health")
        self.assertEqual(public.status_code, 200)
        self.assertIn("max-age=31536000", public.headers["strict-transport-security"])
        self.assertEqual(
            self.client.post("/service/rpc", json={}).status_code,
            401,
        )

    def test_valid_signature_sets_caller_did_and_replay_is_rejected(self) -> None:
        payload = json.dumps({"jsonrpc": "2.0"}, separators=(",", ":")).encode()
        headers = self._signed_request(payload)
        resolver = AsyncMock(return_value=self.caller.did_document)
        with patch(
            "anp.authentication.did_wba_verifier.resolve_did_wba_document",
            resolver,
        ):
            first = self.client.post(
                "/service/rpc",
                content=payload,
                headers=headers,
            )
            replay = self.client.post(
                "/service/rpc",
                content=payload,
                headers=headers,
            )
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["caller"], self.caller.did)
        self.assertEqual(replay.status_code, 401)
        self.assertIn("nonce", replay.text.lower())

    def test_tampered_body_fails_content_digest_verification(self) -> None:
        original = b'{"title":"original"}'
        headers = self._signed_request(original)
        with patch(
            "anp.authentication.did_wba_verifier.resolve_did_wba_document",
            AsyncMock(return_value=self.caller.did_document),
        ):
            response = self.client.post(
                "/service/rpc",
                content=b'{"title":"tampered"}',
                headers=headers,
            )
        self.assertEqual(response.status_code, 401)

    def test_plain_http_and_wrong_authority_are_rejected(self) -> None:
        with TestClient(self.client.app, base_url="http://testserver") as insecure:
            self.assertEqual(insecure.get("/health").status_code, 400)
        self.assertEqual(
            self.client.get("/health", headers={"Host": "evil.test"}).status_code,
            421,
        )


if __name__ == "__main__":
    unittest.main()
