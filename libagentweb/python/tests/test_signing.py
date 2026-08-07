from __future__ import annotations

from base64 import b64decode, b64encode
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from anp.authentication.did_wba import create_did_wba_document
from anp.proof.object_proof import verify_object_proof
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import httpx
from libagentweb import (
    LocalEd25519Signer,
    ManagedDIDWbaAuthHeader,
    VaultTransitEd25519Signer,
    sign_object_proof,
)


def _identity() -> tuple[dict, ed25519.Ed25519PrivateKey]:
    document, keys = create_did_wba_document(
        hostname="caller.example",
        path_segments=["agents", "browser"],
        agent_description_url="https://caller.example/browser/ad.json",
        enable_e2ee=False,
        did_profile="e1",
    )
    key = serialization.load_pem_private_key(keys["key-1"][0], password=None)
    assert isinstance(key, ed25519.Ed25519PrivateKey)
    return document, key


class ManagedSigningTests(unittest.TestCase):
    def test_managed_object_proof_matches_official_anp_verifier(self) -> None:
        did_document, key = _identity()
        did = did_document["id"]
        signed = sign_object_proof(
            {"id": "urn:test:managed-proof", "value": 7},
            signer=LocalEd25519Signer(key, key_id="test-key"),
            issuer_did=did,
            verification_method=f"{did}#key-1",
        )
        result = verify_object_proof(
            signed,
            issuer_did=did,
            issuer_did_document=did_document,
        )
        self.assertEqual(result.issuer_did, did)

    def test_managed_did_auth_never_reads_a_private_key_file(self) -> None:
        document, key = _identity()
        with TemporaryDirectory() as temporary:
            did_path = Path(temporary) / "did.json"
            did_path.write_text(json.dumps(document), encoding="utf-8")
            auth = ManagedDIDWbaAuthHeader(
                str(did_path),
                LocalEd25519Signer(key, key_id="test-key"),
            )
            headers = auth.get_auth_header(
                "https://publisher.example/service/rpc",
                force_new=True,
                method="POST",
                headers={"Content-Type": "application/json"},
                body=b"{}",
            )
            self.assertIn("Signature", headers)
            with self.assertRaisesRegex(RuntimeError, "no process-local"):
                auth._load_private_key()

    def test_vault_transit_adapter_checks_key_type_and_signature(self) -> None:
        key = ed25519.Ed25519PrivateKey.generate()
        public_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.method == "GET":
                return httpx.Response(
                    200,
                    json={
                        "data": {
                            "type": "ed25519",
                            "supports_signing": True,
                            "derived": False,
                            "latest_version": 7,
                            "keys": {"7": {"public_key": public_pem}},
                        }
                    },
                )
            payload = json.loads(request.content)
            signature = key.sign(b64decode(payload["input"]))
            return httpx.Response(
                200,
                json={
                    "data": {
                        "signature": "vault:v7:" + b64encode(signature).decode()
                    }
                },
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        signer = VaultTransitEd25519Signer(
            base_url="https://vault.example",
            mount="agent-web",
            key_name="caller",
            token_provider=lambda: "vault-token",
            client=client,
        )
        signature = signer.sign(b"exact ANP signing input")
        key.public_key().verify(signature, b"exact ANP signing input")
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0].headers["x-vault-token"], "vault-token")
        self.assertNotIn(b"vault-token", requests[1].content)
        self.assertEqual(signer.key_id, "vault-transit:agent-web/caller")
        client.close()

    def test_vault_adapter_rejects_cleartext_endpoint(self) -> None:
        with self.assertRaisesRegex(ValueError, "HTTPS origin"):
            VaultTransitEd25519Signer(
                base_url="http://vault.example",
                mount="transit",
                key_name="caller",
                token_provider=lambda: "token",
            )


if __name__ == "__main__":
    unittest.main()
