from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519

from libagentweb import (
    HttpMessageSignatureError,
    HttpSignatureReplayStore,
    LocalEd25519Signer,
    build_caller_controller,
    sign_agent_web_request,
    verify_agent_web_request,
)


class HttpMessageSignatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.caller = "https://browser.example/.well-known/agent-web-caller"
        self.signer = LocalEd25519Signer(
            ed25519.Ed25519PrivateKey.generate(),
            key_id=f"{self.caller}#key-1",
        )
        self.controller = build_caller_controller(
            caller=self.caller, signer=self.signer
        )
        self.method = "POST"
        self.url = "https://native.example/actions/annotations"
        self.body = b'{"text":"use typed links","topic":"agent-web"}'
        self.now = int(datetime.now(timezone.utc).timestamp())
        self.headers = sign_agent_web_request(
            method=self.method,
            target_uri=self.url,
            body=self.body,
            content_type="application/json",
            caller=self.caller,
            signer=self.signer,
            created=self.now,
            expires=self.now + 120,
            nonce="abcdefghijklmnopqrstuv",
        )

    def test_verifies_full_request_and_rejects_replay(self) -> None:
        with TemporaryDirectory() as temporary:
            store = HttpSignatureReplayStore(Path(temporary) / "nonces.db")
            caller = verify_agent_web_request(
                method=self.method,
                target_uri=self.url,
                body=self.body,
                headers=self.headers,
                controller_document=self.controller,
                replay_store=store,
                now=self.now,
            )
            self.assertEqual(caller.controller, self.caller)
            self.assertTrue(store.integrity_check())
            with self.assertRaisesRegex(HttpMessageSignatureError, "replayed"):
                verify_agent_web_request(
                    method=self.method,
                    target_uri=self.url,
                    body=self.body,
                    headers=self.headers,
                    controller_document=self.controller,
                    replay_store=store,
                    now=self.now,
                )
            store.close()

    def test_body_method_target_and_caller_are_covered(self) -> None:
        cases = (
            {"body": self.body + b" "},
            {"method": "PUT"},
            {"target_uri": self.url + "?redirected=true"},
            {"headers": {**self.headers, "Agent-Web-Caller": "https://attacker.example/id"}},
        )
        for override in cases:
            with self.subTest(override=override):
                arguments = {
                    "method": self.method,
                    "target_uri": self.url,
                    "body": self.body,
                    "headers": self.headers,
                    "controller_document": self.controller,
                    "now": self.now,
                }
                arguments.update(override)
                with self.assertRaises((HttpMessageSignatureError, ValueError)):
                    verify_agent_web_request(**arguments)

    def test_expired_or_unauthorized_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(HttpMessageSignatureError, "expired"):
            verify_agent_web_request(
                method=self.method,
                target_uri=self.url,
                body=self.body,
                headers=self.headers,
                controller_document=self.controller,
                now=self.now + 200,
                clock_skew_seconds=0,
            )
        denied = {**self.controller, "authentication": []}
        with self.assertRaisesRegex(HttpMessageSignatureError, "not authorized"):
            verify_agent_web_request(
                method=self.method,
                target_uri=self.url,
                body=self.body,
                headers=self.headers,
                controller_document=denied,
                now=self.now,
            )

    def test_profile_is_deterministic_and_rfc_shaped(self) -> None:
        self.assertRegex(self.headers["Content-Digest"], r"^sha-256=:.+:$")
        self.assertIn('("@method" "@target-uri"', self.headers["Signature-Input"])
        self.assertIn(';alg="ed25519"', self.headers["Signature-Input"])
        self.assertRegex(self.headers["Signature"], r"^agentweb=:.+:$")

    def test_duplicate_security_fields_are_rejected(self) -> None:
        raw = [
            (name.lower().encode("ascii"), value.encode("ascii"))
            for name, value in self.headers.items()
        ]
        raw.append((b"content-digest", self.headers["Content-Digest"].encode("ascii")))
        with self.assertRaisesRegex(HttpMessageSignatureError, "duplicate"):
            verify_agent_web_request(
                method=self.method,
                target_uri=self.url,
                body=self.body,
                headers=self.headers,
                raw_headers=raw,
                controller_document=self.controller,
                now=self.now,
            )


if __name__ == "__main__":
    unittest.main()
