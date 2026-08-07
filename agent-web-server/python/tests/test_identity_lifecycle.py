from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from agent_web_server import (
    PublisherIdentity,
    ManagedPublisherIdentity,
    generate_publisher_identity,
    load_identity_manifest,
    provision_identity_lifecycle,
    rotate_identity_lifecycle,
)
from anp.proof.object_proof import verify_object_proof
from cryptography.hazmat.primitives.asymmetric import ed25519
from libagentweb import LocalEd25519Signer


class IdentityLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name) / "publisher"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_provision_and_rotate_retains_verified_generations(self) -> None:
        first = provision_identity_lifecycle(
            directory=self.root,
            base_url="https://publisher.example",
            agent_name="moltbook",
            agent_description_path="/moltbook/ad.json",
            handle="moltbook.publisher.example",
        )
        self.assertEqual(PublisherIdentity.from_lifecycle(self.root).did, first.did)
        self.assertEqual(first.handle, "moltbook.publisher.example")
        with self.assertRaises(FileExistsError):
            provision_identity_lifecycle(
                directory=self.root,
                base_url="https://publisher.example",
                agent_name="moltbook",
                agent_description_path="/moltbook/ad.json",
            )

        transition = rotate_identity_lifecycle(
            self.root,
            expected_active_did=first.did,
        )
        active = PublisherIdentity.from_lifecycle(self.root)
        self.assertNotEqual(active.did, first.did)
        self.assertEqual(active.handle, first.handle)
        self.assertEqual(transition["previousDid"], first.did)
        self.assertEqual(transition["successorDid"], active.did)

        manifest = load_identity_manifest(self.root)
        self.assertEqual(manifest["activeGeneration"], 2)
        self.assertEqual(manifest["generations"][0]["status"], "retired")
        self.assertEqual(manifest["generations"][1]["status"], "active")
        old = PublisherIdentity.from_files(
            self.root / manifest["generations"][0]["didDocument"],
            self.root / manifest["generations"][0]["privateKey"],
        )
        payload = {
            name: transition[name]
            for name in (
                "schema",
                "previousDid",
                "successorDid",
                "generation",
                "effectiveAt",
            )
        }
        verify_object_proof(
            {**payload, "proof": transition["previousProof"]},
            issuer_did=old.did,
            issuer_did_document=old.did_document,
        )
        verify_object_proof(
            {**payload, "proof": transition["successorProof"]},
            issuer_did=active.did,
            issuer_did_document=active.did_document,
        )

    def test_managed_publisher_signs_with_did_key_not_access_token_key(self) -> None:
        local = generate_publisher_identity(
            base_url="https://publisher.example",
            agent_name="managed",
            agent_description_path="/managed/ad.json",
        )
        access_token_key = ed25519.Ed25519PrivateKey.generate()
        managed = ManagedPublisherIdentity(
            local.did_document,
            LocalEd25519Signer(local.private_key, key_id="managed-test"),
            access_token_key,
        )
        document = managed.sign_document({"id": "urn:test:publisher"})
        verify_object_proof(
            document,
            issuer_did=managed.did,
            issuer_did_document=managed.did_document,
        )
        self.assertNotEqual(
            managed.public_key_pem,
            local.public_key_pem,
            "JWT access-token key must be separate from the DID assertion key",
        )

    def test_expected_did_and_manifest_path_controls_fail_closed(self) -> None:
        first = provision_identity_lifecycle(
            directory=self.root,
            base_url="https://publisher.example",
            agent_name="forecast",
            agent_description_path="/forecast/ad.json",
        )
        with self.assertRaises(ValueError):
            rotate_identity_lifecycle(
                self.root,
                expected_active_did=first.did + "-stale",
            )

        manifest_path = self.root / "manifest.json"
        document = load_identity_manifest(self.root)
        document["generations"][0]["privateKey"] = "../../outside.pem"
        manifest_path.write_text(
            __import__("json").dumps(document),
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            PublisherIdentity.from_lifecycle(self.root)


if __name__ == "__main__":
    unittest.main()
