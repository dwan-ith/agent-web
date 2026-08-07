"""Live preflight proving a Vault Transit key matches an Agent Web DID."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
from secrets import token_bytes

from anp.authentication.verification_methods import create_verification_method
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from libagentweb import VaultTransitEd25519Signer


def _secret(path: str) -> str:
    value = Path(path).read_text(encoding="utf-8").strip()
    if not value or "\n" in value or "\r" in value or len(value) > 4096:
        raise ValueError("Vault token file must contain one bounded value")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--did-document", required=True)
    parser.add_argument("--vault-url", required=True)
    parser.add_argument("--vault-mount", default="transit")
    parser.add_argument("--vault-key", required=True)
    parser.add_argument("--vault-token-file", required=True)
    parser.add_argument("--vault-namespace")
    parser.add_argument("--vault-ca-file")
    args = parser.parse_args()
    document = json.loads(Path(args.did_document).read_text(encoding="utf-8"))
    methods = document.get("verificationMethod", [])
    expected = None
    for method in methods:
        if isinstance(method, dict) and method.get("id") == f"{document['id']}#key-1":
            verifier = create_verification_method(method)
            public = getattr(verifier, "public_key", None)
            if isinstance(public, ed25519.Ed25519PublicKey):
                expected = public.public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
    if expected is None:
        raise ValueError("DID has no Ed25519 #key-1 verification method")
    signer = VaultTransitEd25519Signer(
        base_url=args.vault_url,
        mount=args.vault_mount,
        key_name=args.vault_key,
        token_provider=lambda: _secret(args.vault_token_file),
        namespace=args.vault_namespace,
        ca_file=args.vault_ca_file,
    )
    try:
        actual = signer.public_key_bytes()
        if actual != expected:
            raise ValueError("Vault key does not match the DID verification method")
        challenge = token_bytes(32)
        signature = signer.sign(challenge)
        ed25519.Ed25519PublicKey.from_public_bytes(actual).verify(
            signature, challenge
        )
    finally:
        signer.close()
    print(
        json.dumps(
            {
                "status": "passed",
                "did": document["id"],
                "keyId": signer.key_id,
                "publicKeySha256": sha256(actual).hexdigest(),
                "challengeSignatureVerified": True,
                "privateKeyExported": False,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
