from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import unittest

from anp.authentication.did_wba import create_did_wba_document
from cryptography.hazmat.primitives import serialization
from libagentweb import (
    ResourceTrustError,
    empty_affordances,
    sign_resource,
    verify_resource,
)


class SignedResourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.did_document, keys = create_did_wba_document(
            hostname="publisher.test",
            path_segments=["agents", "example"],
            agent_description_url="https://publisher.test/example/ad.json",
            enable_e2ee=False,
        )
        self.private_key = serialization.load_pem_private_key(
            keys["key-1"][0],
            password=None,
        )
        self.did = self.did_document["id"]

    def resource(self) -> dict:
        now = datetime.now(timezone.utc)
        timestamp = now.isoformat().replace("+00:00", "Z")
        return {
            "@context": "urn:agent-web:context:0.2",
            "@id": "https://publisher.test/example/resources/one.json",
            "@type": "AgentWebResource",
            "agentWeb": {"version": "0.2", "kind": "resource"},
            "name": "One",
            "links": [],
            "affordances": empty_affordances(),
            "provenance": {
                "publisher": self.did,
                "createdAt": timestamp,
                "updatedAt": timestamp,
                "expiresAt": (
                    now + timedelta(minutes=5)
                ).isoformat().replace("+00:00", "Z"),
                "canonical": "https://publisher.test/example/resources/one.json",
            },
            "data": {"value": 1},
        }

    def test_real_object_proof_verifies(self) -> None:
        signed = sign_resource(
            self.resource(),
            private_key=self.private_key,
            publisher_did=self.did,
        )
        verified = verify_resource(
            signed,
            publisher_did_document=self.did_document,
        )
        self.assertEqual(verified["data"]["value"], 1)

    def test_tampered_resource_is_rejected(self) -> None:
        signed = sign_resource(
            self.resource(),
            private_key=self.private_key,
            publisher_did=self.did,
        )
        tampered = deepcopy(signed)
        tampered["data"]["value"] = 999
        with self.assertRaises(ResourceTrustError):
            verify_resource(
                tampered,
                publisher_did_document=self.did_document,
            )


if __name__ == "__main__":
    unittest.main()
