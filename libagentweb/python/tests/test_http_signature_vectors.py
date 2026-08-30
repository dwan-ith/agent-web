"""Cross-language conformance for the strict HTTP-signature profile.

The committed vector file pins byte-exact wire output and every rejection
reason. The TypeScript implementation must satisfy the identical file; the
committed copies in both trees must also stay byte-identical.
"""

from __future__ import annotations

from base64 import b64decode
from pathlib import Path
import unittest

from libagentweb.http_signatures import (
    CALLER_HEADER,
    HttpMessageSignatureError,
    HttpSignatureReplayStore,
    build_caller_controller,
    sign_agent_web_request,
    verify_agent_web_request,
)
from libagentweb.signing import LocalEd25519Signer
import base58

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
VECTORS = (
    REPOSITORY_ROOT
    / "libagentweb/conformance/http-signatures/http-signatures.vectors.json"
)


def load_vectors() -> dict:
    import json

    return json.loads(VECTORS.read_text(encoding="utf-8"))


class HttpSignatureVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = load_vectors()
        cls.signer = LocalEd25519Signer(
            __import__(
                "cryptography.hazmat.primitives.asymmetric.ed25519",
                fromlist=["Ed25519PrivateKey"],
            ).Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(cls.document["key"]["seedHex"])
            ),
            key_id=cls.document["key"]["keyId"],
        )

    def test_committed_copies_are_identical(self) -> None:
        typescript_copy = (
            REPOSITORY_ROOT
            / "libagentweb/typescript/src/vectors/http-signatures.vectors.json"
        )
        self.assertEqual(
            VECTORS.read_bytes(),
            typescript_copy.read_bytes(),
            "TypeScript vector copy has drifted from the canonical file",
        )

    def test_seed_derives_the_committed_multikey(self) -> None:
        encoded = b"\xed\x01" + self.signer.public_key_bytes()
        self.assertEqual(
            self.document["key"]["publicKeyMultibase"],
            "z" + base58.b58encode(encoded).decode("ascii"),
        )

    def test_signing_reproduces_every_committed_header(self) -> None:
        request = self.document["request"]
        headers = sign_agent_web_request(
            method=request["method"],
            target_uri=request["targetUri"],
            body=b64decode(request["bodyBase64"]),
            content_type=request["contentType"],
            caller=request["caller"],
            signer=self.signer,
            created=self.document["fixed"]["created"],
            expires=self.document["fixed"]["expires"],
            nonce=self.document["fixed"]["nonce"],
        )
        lowered = {key.lower(): value for key, value in headers.items()}
        self.assertEqual(lowered, self.document["expectedHeaders"])

    def test_controller_matches_the_derived_key(self) -> None:
        self.assertEqual(
            build_caller_controller(
                caller=self.document["request"]["caller"],
                signer=self.signer,
            ),
            self.document["callerController"],
        )

    def _verify(self, case: dict) -> None:
        request = self.document["request"]
        headers = dict(self.document["expectedHeaders"])
        for name, value in (case.get("headers") or {}).items():
            headers[name.lower()] = value
        controller = case.get("controllerDocument") or self.document[
            "callerController"
        ]
        return verify_agent_web_request(
            method=case.get("method", request["method"]),
            target_uri=case.get("targetUri", request["targetUri"]),
            body=b64decode(case.get("bodyBase64", request["bodyBase64"])),
            headers=headers,
            controller_document=controller,
            now=case.get("verifyNow", self.document["fixed"]["now"]),
        )

    def test_verification_accepts_the_positive_vector(self) -> None:
        caller = self._verify({})
        self.assertEqual(caller.controller, self.document["request"]["caller"])
        self.assertEqual(caller.nonce, self.document["fixed"]["nonce"])

    def test_nonce_replay_is_claimed_exactly_once(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as value:
            store = HttpSignatureReplayStore(Path(value) / "nonces.db")
            try:
                request = self.document["request"]
                kwargs = dict(
                    method=request["method"],
                    target_uri=request["targetUri"],
                    body=b64decode(request["bodyBase64"]),
                    headers=dict(self.document["expectedHeaders"]),
                    controller_document=self.document["callerController"],
                    replay_store=store,
                    now=self.document["fixed"]["now"],
                )
                verify_agent_web_request(**kwargs)
                with self.assertRaisesRegex(HttpMessageSignatureError, "replayed"):
                    verify_agent_web_request(**kwargs)
            finally:
                store.close()

    def test_every_negative_vector_is_rejected_with_its_reason(self) -> None:
        for case in self.document["negatives"]:
            with self.subTest(case=case["name"]):
                with self.assertRaisesRegex(
                    HttpMessageSignatureError,
                    case["expectedError"].replace("+", r"\+"),
                ):
                    self._verify(case)

    def test_caller_header_name_matches_python_constant(self) -> None:
        self.assertIn(CALLER_HEADER.lower(), self.document["expectedHeaders"])


if __name__ == "__main__":
    unittest.main()
