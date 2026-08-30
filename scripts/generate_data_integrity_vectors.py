"""Generate committed cross-language Data Integrity proof vectors.

Every vector fixes the Ed25519 seed (RFC 8032 test vector 1, publicly known
and therefore safe) and timestamps so Ed25519 determinism makes the expected
proof byte-stable forever. The Python implementation signs the positive
vector and classifies every negative vector; the TypeScript implementation
MUST verify the positive vector and reject every negative vector with the
documented reason. Both implementations consume this exact committed file,
which also pins the RFC 8785 canonical form of the unsigned document.

Run from the repository root:

    .\\.venv\\Scripts\\python.exe scripts\\generate_data_integrity_vectors.py

A regeneration that changes a committed file means an implementation or
profile change escaped review.
"""

from __future__ import annotations

import jcs
import json
from pathlib import Path

import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from libagentweb.signing import LocalEd25519Signer, sign_object_proof

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = (
    ROOT / "libagentweb/conformance/data-integrity/data-integrity.vectors.json"
)
TYPESCRIPT_COPY = (
    ROOT / "libagentweb/typescript/src/vectors/data-integrity.vectors.json"
)

# Project-fixed conformance seed, shared with the HTTP-signature vectors. It
# is committed here on purpose: it protects nothing and lets every
# implementation reproduce the exact keys.
SEED = bytes.fromhex(
    "9d61b19deffd2a60588dc0da7f0c4b1dd0e86ab4a0f2e4ac17432c21de4649ec"
)
SECOND_SEED = bytes(range(1, 33))

ORIGIN = "https://publisher.example"
PUBLISHER = f"{ORIGIN}/.well-known/agent-web"
METHOD = f"{PUBLISHER}#key-1"
CREATED = "2026-08-01T00:00:00Z"


def _multikey(seed: bytes) -> str:
    key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return "z" + base58.b58encode(b"\xed\x01" + public).decode("ascii")


def _unsigned_document() -> dict:
    # The data exercises RFC 8785 key ordering (including a key that needs
    # escaping and non-ASCII keys), number formatting, and nested structures.
    return {
        "@context": "urn:agent-web:context:0.2",
        "@id": f"{ORIGIN}/resources/vector",
        "@type": ["AgentWebResource", "ConformanceVector"],
        "agentWeb": {"version": "0.2", "kind": "resource"},
        "name": "Data Integrity conformance vector",
        "description": "Cross-language eddsa-jcs-2022 verification fixture.",
        "links": [
            {
                "rel": "self",
                "href": f"{ORIGIN}/resources/vector",
                "mediaType": "application/agent-web+json",
            }
        ],
        "affordances": {"properties": {}, "actions": {}, "events": {}},
        "provenance": {
            "publisher": PUBLISHER,
            "createdAt": CREATED,
            "updatedAt": CREATED,
            "canonical": f"{ORIGIN}/resources/vector",
        },
        "data": {
            "zeta": 1,
            "Alpha": [1, 2.5, -3, True, None],
            "naïve": "café",
            "quote\"key": "escaped",
            "nested": {"b": 2, "a": {"y": [10, 0.125], "x": "order"}},
            "count": 300,
        },
    }


def main() -> None:
    signer = LocalEd25519Signer(
        ed25519.Ed25519PrivateKey.from_private_bytes(SEED),
        key_id=METHOD,
    )
    signed = sign_object_proof(
        _unsigned_document(),
        signer=signer,
        issuer_did=PUBLISHER,
        verification_method=METHOD,
        created=CREATED,
    )
    unsigned = {key: value for key, value in signed.items() if key != "proof"}
    controller = {
        "id": PUBLISHER,
        "verificationMethod": [
            {
                "id": METHOD,
                "type": "Multikey",
                "controller": PUBLISHER,
                "publicKeyMultibase": _multikey(SEED),
            }
        ],
        "assertionMethod": [METHOD],
    }

    second_signer = LocalEd25519Signer(
        ed25519.Ed25519PrivateKey.from_private_bytes(SECOND_SEED),
        key_id=METHOD,
    )
    wrong_key = sign_object_proof(
        _unsigned_document(),
        signer=second_signer,
        issuer_did=PUBLISHER,
        verification_method=METHOD,
        created=CREATED,
    )

    def variant(**changes) -> dict:
        document = json.loads(json.dumps(signed))
        for path, value in changes.items():
            target: dict = document
            parts = path.split(".")
            for part in parts[:-1]:
                target = target[part]
            if value is None:
                del target[parts[-1]]
            else:
                target[parts[-1]] = value
        return document

    tampered = json.loads(json.dumps(signed))
    tampered["data"]["zeta"] = 2

    # Flip one bit in the decoded signature: still exactly 64 bytes, still
    # well-formed base58-btc, but cryptographically wrong.
    corrupted_signature = bytearray(
        base58.b58decode(signed["proof"]["proofValue"][1:])
    )
    corrupted_signature[63] ^= 0x80
    corrupt_value = (
        "z" + base58.b58encode(bytes(corrupted_signature)).decode("ascii")
    )

    vectors = {
        "profile": "urn:agent-web:data-integrity:0.1",
        "cryptosuite": "eddsa-jcs-2022",
        "fixed": {"created": CREATED, "origin": ORIGIN, "publisher": PUBLISHER},
        "keys": {
            "seedHex": SEED.hex(),
            "secondSeedHex": SECOND_SEED.hex(),
            "publicKeyMultibase": _multikey(SEED),
        },
        "controllerDocument": controller,
        "resource": signed,
        # Committed RFC 8785 expectation so every language asserts its
        # canonicalizer byte-for-byte before touching cryptography.
        "canonicalUnsignedDocument": jcs.canonicalize(unsigned).decode("utf-8"),
        "negatives": [
            {
                "name": "tampered-data",
                "expectedError": "signature is invalid",
                "resource": tampered,
            },
            {
                "name": "signed-by-different-key",
                "expectedError": "signature is invalid",
                "resource": wrong_key,
            },
            {
                "name": "unauthorized-assertion-method",
                "expectedError": "not authorized for assertions",
                "resource": signed,
                "controllerDocument": {
                    **controller,
                    "assertionMethod": [],
                },
            },
            {
                "name": "unknown-verification-method",
                "expectedError": "not published",
                "resource": signed,
                "controllerDocument": {
                    **controller,
                    "verificationMethod": [],
                },
            },
            {
                "name": "issuer-mismatch",
                "expectedError": "does not belong to issuer",
                "resource": signed,
                "issuer": "https://attacker.example/.well-known/agent-web",
            },
            {
                "name": "wrong-cryptosuite",
                "expectedError": "unsupported proof cryptosuite",
                "resource": variant(**{"proof.cryptosuite": "ecdsa-rdfc-2019"}),
            },
            {
                "name": "corrupt-proof-value",
                "expectedError": "signature is invalid",
                "resource": variant(**{"proof.proofValue": corrupt_value}),
            },
            {
                "name": "tampered-proof-created",
                "expectedError": "signature is invalid",
                "resource": variant(**{"proof.created": "2026-08-02T00:00:00Z"}),
            },
            {
                "name": "missing-proof",
                "expectedError": "no Data Integrity proof",
                "resource": unsigned,
            },
        ],
    }

    CANONICAL.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(vectors, ensure_ascii=False, indent=2) + "\n"
    CANONICAL.write_text(payload, encoding="utf-8")
    TYPESCRIPT_COPY.parent.mkdir(parents=True, exist_ok=True)
    TYPESCRIPT_COPY.write_text(payload, encoding="utf-8")
    print(f"wrote {CANONICAL}")
    print(f"wrote {TYPESCRIPT_COPY}")


if __name__ == "__main__":
    main()
