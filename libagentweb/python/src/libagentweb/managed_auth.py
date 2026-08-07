"""DID-WBA HTTP signatures backed by an external Ed25519 signer."""

from __future__ import annotations

from typing import Any

from anp.authentication import DIDWbaAuthHeader
from anp.authentication.verification_methods import create_verification_method
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .signing import Ed25519Signer


class ManagedDIDWbaAuthHeader(DIDWbaAuthHeader):
    """ANP auth helper that never loads a private key from the filesystem."""

    def __init__(self, did_document_path: str, signer: Ed25519Signer) -> None:
        super().__init__(
            did_document_path=did_document_path,
            private_key_path="managed://private-key-unavailable",
            auth_mode="http_signatures",
        )
        self.signer = signer
        self._method_fragment: str | None = None

    def _load_did_document(self) -> dict[str, Any]:
        document = super()._load_did_document()
        if self._method_fragment is None:
            matches: list[str] = []
            expected = self.signer.public_key_bytes()
            if len(expected) != 32:
                raise ValueError("managed Ed25519 public key must contain 32 bytes")
            for method in document.get("verificationMethod", []):
                if not isinstance(method, dict) or not isinstance(method.get("id"), str):
                    continue
                verifier = create_verification_method(method)
                public = getattr(verifier, "public_key", None)
                if not isinstance(public, ed25519.Ed25519PublicKey):
                    continue
                actual = public.public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
                if actual == expected:
                    matches.append(method["id"].split("#", 1)[-1])
            if len(matches) != 1:
                raise ValueError(
                    "managed signer must match exactly one DID verification method"
                )
            self._method_fragment = matches[0]
        return document

    def _load_private_key(self) -> Any:
        raise RuntimeError("managed authentication has no process-local private key")

    def _sign_callback(self, content: bytes, method_fragment: str) -> bytes:
        self._load_did_document()
        if method_fragment.lstrip("#") != self._method_fragment:
            raise ValueError("ANP requested an unexpected verification method")
        signature = self.signer.sign(content)
        if len(signature) != 64:
            raise ValueError("managed Ed25519 signer returned an invalid signature")
        ed25519.Ed25519PublicKey.from_public_bytes(
            self.signer.public_key_bytes()
        ).verify(signature, content)
        return signature
