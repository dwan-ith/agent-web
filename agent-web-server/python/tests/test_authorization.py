from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from agent_web_server import AuthorizationStore, RpcAuthorizationRule
from agent_web_server.authorization import install_rpc_authorization
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient


def _build_client(store: AuthorizationStore) -> TestClient:
    app = FastAPI()

    @app.post("/rpc")
    async def rpc(request: Request) -> JSONResponse:
        payload = await request.json()
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "result": {"echo": payload.get("params")},
                "id": payload.get("id"),
            }
        )

    install_rpc_authorization(
        app,
        store,
        rpc_path="/rpc",
        rules={
            "create_thread": RpcAuthorizationRule(
                action="moltbook:create_thread",
                resource=lambda params: params["resource"],
            ),
        },
    )

    @app.middleware("http")
    async def fake_authentication(request: Request, call_next):
        caller = request.headers.get("x-test-caller")
        request.state.did = caller or None
        return await call_next(request)

    return TestClient(app)


class RpcAuthorizationMiddlewareTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.store = AuthorizationStore(Path(self.temp.name) / "authorization.db")
        self.subject = "did:wba:caller.example:agents:browser:e1:test"
        self.resource = "https://forum.example/moltbook/resources/index.json"
        self.client = _build_client(self.store)

    def tearDown(self) -> None:
        self.client.close()
        self.store.close()
        self.temp.cleanup()

    def _post(self, *, method: str = "create_thread", **overrides):
        payload = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": method,
            "params": {"resource": self.resource},
        }
        payload.update(overrides)
        headers = overrides.pop("headers", {})
        if self.subject:
            headers["x-test-caller"] = self.subject
        return self.client.post("/rpc", json=payload, headers=headers)

    def test_unauthenticated_protected_method_is_denied_with_did_required(self) -> None:
        response = self.client.post(
            "/rpc",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "create_thread",
                "params": {"resource": self.resource},
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["error"]["code"], -32002)
        self.assertIn(
            "authenticated DID",
            response.json()["error"]["data"]["reason"],
        )

    def test_granted_caller_reaches_route_and_consumes_its_grant(self) -> None:
        grant_id = self.store.grant(
            subject_did=self.subject,
            action="moltbook:create_thread",
            resource=self.resource,
            max_uses=1,
        )
        allowed = self._post()
        self.assertNotIn("error", allowed.json())
        self.assertEqual(allowed.json()["result"]["echo"]["resource"], self.resource)
        exhausted = self._post()
        self.assertEqual(exhausted.json()["error"]["code"], -32002)
        self.assertEqual(exhausted.json()["error"]["data"]["reason"], "grant exhausted")
        uses = {
            row["grant_id"]: row["uses"] for row in self.store.list_grants()
        }
        self.assertEqual(uses[grant_id], 1)

    def test_ungranted_caller_is_denied_without_touching_the_route(self) -> None:
        denied = self._post()
        self.assertEqual(denied.json()["error"]["code"], -32002)
        self.assertEqual(denied.json()["error"]["data"]["reason"], "no matching grant")

    def test_unresolvable_resource_returns_invalid_params(self) -> None:
        self.store.grant(
            subject_did=self.subject,
            action="moltbook:create_thread",
            resource=self.resource,
        )
        missing = self._post(params={})
        self.assertEqual(missing.json()["error"]["code"], -32602)
        non_string = self._post(params={"resource": ["https://not-a-scope"]})
        self.assertEqual(non_string.json()["error"]["code"], -32602)

    def test_batch_requests_containing_protected_methods_are_rejected(self) -> None:
        batch = [
            {"jsonrpc": "2.0", "id": 1, "method": "unprotected"},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "create_thread",
                "params": {"resource": self.resource},
            },
        ]
        response = self.client.post("/rpc", json=batch)
        self.assertEqual(response.json()["error"]["code"], -32600)

    def test_authorization_store_failure_becomes_json_rpc_error_not_http_500(self) -> None:
        self.store.grant(
            subject_did=self.subject,
            action="moltbook:create_thread",
            resource=self.resource,
        )
        self.store.close()
        response = self._post()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["error"]["code"], -32001)


class AuthorizationStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.store = AuthorizationStore(Path(self.temp.name) / "authorization.db")
        self.subject = "did:wba:caller.example:agents:browser:e1:test"
        self.collection = "https://forum.example/moltbook/resources/index.json"
        self.thread_prefix = "https://forum.example/moltbook/resources/threads/"

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_default_deny_and_exact_action_subject_and_resource_matching(self) -> None:
        denied = self.store.authorize(
            subject_did=self.subject,
            action="moltbook:create_thread",
            resource=self.collection,
        )
        self.assertFalse(denied.allowed)

        grant_id = self.store.grant(
            subject_did=self.subject,
            action="moltbook:create_thread",
            resource=self.collection,
        )
        allowed = self.store.authorize(
            subject_did=self.subject,
            action="moltbook:create_thread",
            resource=self.collection,
        )
        self.assertTrue(allowed.allowed)
        self.assertEqual(allowed.grant_id, grant_id)
        self.assertFalse(
            self.store.authorize(
                subject_did=self.subject,
                action="moltbook:create_reply",
                resource=self.collection,
            ).allowed
        )
        self.assertFalse(
            self.store.authorize(
                subject_did="did:wba:other.example:agents:browser:e1:test",
                action="moltbook:create_thread",
                resource=self.collection,
            ).allowed
        )

    def test_prefix_expiry_usage_limit_and_revocation_are_enforced(self) -> None:
        now = datetime.now(timezone.utc)
        grant_id = self.store.grant(
            subject_did=self.subject,
            action="moltbook:create_reply",
            resource=self.thread_prefix,
            scope_type="prefix",
            expires_at=now + timedelta(minutes=5),
            max_uses=1,
        )
        first = self.store.authorize(
            subject_did=self.subject,
            action="moltbook:create_reply",
            resource=f"{self.thread_prefix}abc.json",
            now=now,
        )
        exhausted = self.store.authorize(
            subject_did=self.subject,
            action="moltbook:create_reply",
            resource=f"{self.thread_prefix}def.json",
            now=now,
        )
        self.assertTrue(first.allowed)
        self.assertEqual(exhausted.reason, "grant exhausted")

        expiring = self.store.grant(
            subject_did=self.subject,
            action="moltbook:edit_thread",
            resource=f"{self.thread_prefix}expiring.json",
            expires_at=now + timedelta(seconds=1),
        )
        expired = self.store.authorize(
            subject_did=self.subject,
            action="moltbook:edit_thread",
            resource=f"{self.thread_prefix}expiring.json",
            now=now + timedelta(seconds=2),
        )
        self.assertEqual(expired.reason, "grant expired")

        revoked = self.store.grant(
            subject_did=self.subject,
            action="moltbook:create_thread",
            resource=self.collection,
        )
        self.assertTrue(self.store.revoke(revoked))
        self.assertFalse(self.store.revoke(revoked))
        self.assertFalse(
            self.store.authorize(
                subject_did=self.subject,
                action="moltbook:create_thread",
                resource=self.collection,
            ).allowed
        )
        self.assertEqual(
            self.store.list_grants()[0]["grant_id"],
            grant_id,
        )
        self.assertEqual(expiring, self.store.list_grants()[1]["grant_id"])
        self.assertEqual(len(self.store.audit_log()), 4)

    def test_scope_validation_rejects_ambiguous_or_broad_inputs(self) -> None:
        with self.assertRaises(ValueError):
            self.store.grant(
                subject_did="*",
                action="moltbook:create_thread",
                resource=self.collection,
            )
        with self.assertRaises(ValueError):
            self.store.grant(
                subject_did=self.subject,
                action="*",
                resource=self.collection,
            )
        with self.assertRaises(ValueError):
            self.store.grant(
                subject_did=self.subject,
                action="moltbook:create_reply",
                resource="https://forum.example/moltbook/resources/threads",
                scope_type="prefix",
            )
        with self.assertRaises(ValueError):
            self.store.grant(
                subject_did=self.subject,
                action="moltbook:create_thread",
                resource="http://forum.example/insecure",
            )

    def test_audit_retention_keeps_the_newest_decisions(self) -> None:
        self.store._audit_retention = 1000
        self.store.grant(
            subject_did=self.subject,
            action="moltbook:create_thread",
            resource=self.collection,
        )
        for _ in range(1003):
            decision = self.store.authorize(
                subject_did=self.subject,
                action="moltbook:create_thread",
                resource=self.collection,
                consume=False,
            )
            self.assertTrue(decision.allowed)
        audit = self.store.audit_log(limit=1000)
        self.assertEqual(len(audit), 1000)
        # The bounded trail keeps the newest decisions: the newest retained
        # row must be the 1003rd decision, not the first ever recorded.
        self.assertEqual(audit[0]["sequence"], 1003)


if __name__ == "__main__":
    unittest.main()
