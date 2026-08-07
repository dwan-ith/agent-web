from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import AsyncMock, patch

from agent_web_server import generate_publisher_identity, write_identity
from anp.authentication import DIDWbaAuthHeader
from anp.proof.object_proof import verify_object_proof
from fastapi.testclient import TestClient
from libagentweb import RESOURCE_MEDIA_TYPE, verify_resource
from moltbook_site.app import create_app


class SecureMoltbookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        root = Path(self.temp.name)
        self.publisher = generate_publisher_identity(
            base_url="https://testserver",
            agent_name="moltbook",
            agent_description_path="/moltbook/ad.json",
        )
        self.caller = generate_publisher_identity(
            base_url="https://caller.test",
            agent_name="browser",
            agent_description_path="/browser/ad.json",
        )
        did_path, key_path = write_identity(
            self.caller,
            directory=root / "caller",
        )
        self.auth = DIDWbaAuthHeader(str(did_path), str(key_path))
        self.metrics_token = "m" * 32
        self.app = create_app(
            base_url="https://testserver",
            identity=self.publisher,
            database=root / "moltbook.db",
            nonce_database=root / "nonces.db",
            seed=False,
            metrics_token=self.metrics_token,
            operator_token="o" * 32,
        )
        self.create_thread_grant = self.app.state.authorization_store.grant(
            subject_did=self.caller.did,
            action="moltbook:create_thread",
            resource="https://testserver/moltbook/resources/index.json",
        )
        self.app.state.authorization_store.grant(
            subject_did=self.caller.did,
            action="moltbook:create_reply",
            resource="https://testserver/moltbook/resources/threads/",
            scope_type="prefix",
        )
        self.client = TestClient(self.app, base_url="https://testserver")

    def tearDown(self) -> None:
        self.client.close()
        self.app.state.close()
        self.temp.cleanup()

    def rpc_document(self, method: str, params: dict) -> dict:
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": "test",
            },
            separators=(",", ":"),
        ).encode()
        base_headers = {"Content-Type": "application/json"}
        headers = {
            **base_headers,
            **self.auth.get_auth_header(
                "https://testserver/moltbook/rpc",
                force_new=True,
                method="POST",
                headers=base_headers,
                body=payload,
            ),
        }
        with patch(
            "anp.authentication.did_wba_verifier.resolve_did_wba_document",
            AsyncMock(return_value=self.caller.did_document),
        ):
            response = self.client.post(
                "/moltbook/rpc",
                content=payload,
                headers=headers,
            )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def rpc(self, method: str, params: dict) -> object:
        document = self.rpc_document(method, params)
        self.assertNotIn("error", document, document)
        return document["result"]

    def test_authenticated_but_ungranted_mutation_is_denied_and_audited(self) -> None:
        self.assertTrue(
            self.app.state.authorization_store.revoke(
                self.create_thread_grant
            )
        )
        document = self.rpc_document(
            "create_thread",
            {"title": "Denied", "body": "Authentication is not authorization."},
        )
        self.assertEqual(document["error"]["code"], -32002)
        self.assertEqual(
            document["error"]["message"],
            "Authorization denied",
        )
        audit = self.app.state.authorization_store.audit_log()
        self.assertFalse(audit[0]["allowed"])
        self.assertEqual(audit[0]["subject_did"], self.caller.did)
        self.assertEqual(audit[0]["action"], "moltbook:create_thread")

    def test_discovery_did_and_resources_have_real_object_proofs(self) -> None:
        description = self.client.get("/moltbook/ad.json").json()
        verify_object_proof(
            description,
            issuer_did=self.publisher.did,
            issuer_did_document=self.publisher.did_document,
        )
        self.assertEqual(description["identifier"], self.publisher.did)
        self.assertEqual(description["agentWeb"]["version"], "0.2")
        self.assertEqual(
            description["security"]["authorization"],
            "operator-scoped-grants",
        )

        did_path = "/" + "/".join(self.publisher.did.split(":")[3:]) + "/did.json"
        hosted_did = self.client.get(did_path)
        self.assertEqual(hosted_did.status_code, 200)
        self.assertEqual(hosted_did.json(), self.publisher.did_document)

        resource = self.client.get(
            "/moltbook/resources/index.json"
        ).json()
        verify_resource(
            resource,
            publisher_did_document=self.publisher.did_document,
        )
        ready = self.client.get("/ready")
        self.assertEqual(ready.status_code, 200, ready.text)
        self.assertTrue(all(ready.json()["components"].values()))
        self.assertEqual(self.client.get("/metrics").status_code, 401)
        metrics = self.client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {self.metrics_token}"},
        )
        self.assertEqual(metrics.status_code, 200, metrics.text)
        self.assertIn("agent_web_ready", metrics.text)

    def test_mutation_requires_auth_and_author_is_not_caller_controlled(self) -> None:
        anonymous = self.client.post(
            "/moltbook/rpc",
            json={
                "jsonrpc": "2.0",
                "method": "create_thread",
                "params": {"title": "No", "body": "Anonymous"},
                "id": 1,
            },
        )
        self.assertEqual(anonymous.status_code, 401)

        resource = self.rpc(
            "create_thread",
            {
                "title": "Authenticated authorship",
                "body": "The server derives this author from the signature.",
            },
        )
        self.assertEqual(resource["data"]["author"], self.caller.did)
        verify_resource(
            resource,
            publisher_did_document=self.publisher.did_document,
        )
        thread_id = resource["data"]["threadId"]
        machine = self.client.get(
            f"/moltbook/resources/threads/{thread_id}.json"
        )
        self.assertTrue(
            machine.headers["content-type"].startswith(RESOURCE_MEDIA_TYPE)
        )
        self.assertEqual(machine.json()["data"]["author"], self.caller.did)
        human = self.client.get(f"/forum/threads/{thread_id}")
        self.assertIn("Authenticated authorship", human.text)
        self.assertIn(self.caller.did, human.text)
        self.assertIn(resource["@id"], human.headers["link"])

        audit = self.app.state.moltbook_store.audit_log()
        self.assertEqual(audit[0]["actor"], self.caller.did)
        self.assertEqual(audit[0]["action"], "create_thread")

    def test_action_contract_requires_user_presence_and_no_author_field(self) -> None:
        entry = self.client.get("/moltbook/resources/index.json").json()
        action = entry["affordances"]["actions"]["createThread"]
        self.assertEqual(
            action["authorizationLevel"],
            "user-presence-required",
        )
        self.assertNotIn("author", action["input"]["properties"])


if __name__ == "__main__":
    unittest.main()
