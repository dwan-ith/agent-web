from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from agent_web_server import AuthorizationStore


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


if __name__ == "__main__":
    unittest.main()
