"""Generate committed cross-language HTTP-signature conformance vectors.

Every vector fixes the Ed25519 seed (RFC 8032 test vector 1, publicly known
and therefore safe), timestamps, and nonce so Ed25519 determinism makes the
expected wire fields byte-stable forever. Two implementations (Python and
TypeScript) MUST produce identical headers for the positive vector and
reject every negative vector with the documented reason.

Negative vectors are self-contained: ``headers`` entries replace the matching
positive-vector header values, ``bodyBase64``/``method``/``targetUri``
replace the request fields, ``controllerDocument`` replaces the controller,
and ``verifyNow`` overrides verification time.

Run from the repository root:

    .\\.venv\\Scripts\\python.exe scripts\\generate_http_signature_vectors.py

A regeneration that changes a committed file means an implementation or
profile change escaped review.
"""

from __future__ import annotations

from base64 import b64decode, b64encode
from pathlib import Path
import json

import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from libagentweb.http_signatures import (
    CALLER_HEADER,
    build_caller_controller,
    sign_agent_web_request,
)
from libagentweb.signing import LocalEd25519Signer

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = (
    ROOT / "libagentweb/conformance/http-signatures/http-signatures.vectors.json"
)
TYPESCRIPT_COPY = (
    ROOT / "libagentweb/typescript/src/vectors/http-signatures.vectors.json"
)

# Project-fixed conformance seed. It is committed here on purpose: it
# protects nothing and lets every implementation reproduce the exact keys.
SEED = bytes.fromhex(
    "9d61b19deffd2a60588dc0da7f0c4b1dd0e86ab4a0f2e4ac17432c21de4649ec"
)

# A second independent key for the cross-key rejection vector.
SECOND_SEED = bytes(range(1, 33))

CALLER = "https://browser.example/.well-known/agent-web-caller"
KEY_ID = f"{CALLER}#key-1"
CREATED = 1_760_000_000
EXPIRES = 1_760_000_120
NONCE = "agent-web-conformance-nonce-001"

REQUEST = {
    "method": "POST",
    "targetUri": "https://native.example/actions/annotations",
    "bodyBase64": b64encode(
        '{"topic":"conformance","text":"cross-language vector"}'.encode("utf-8")
    ).decode("ascii"),
    "contentType": "application/json",
    "caller": CALLER,
}


def _multibase(
    key: ed25519.Ed25519PrivateKey
    | ed25519.Ed25519PublicKey
    | bytes,
) -> str:
    if isinstance(key, bytes):
        raw = key
    else:
        if isinstance(key, ed25519.Ed25519PrivateKey):
            key = key.public_key()
        raw = key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    return "z" + base58.b58encode(b"\xed\x01" + raw).decode("ascii")


def _signer(seed: bytes) -> LocalEd25519Signer:
    return LocalEd25519Signer(
        ed25519.Ed25519PrivateKey.from_private_bytes(seed),
        key_id=KEY_ID,
    )


def _second_controller(controller: dict) -> dict:
    """Same identities, different published key: signatures must fail."""

    return {
        **controller,
        "verificationMethod": [
            {
                **controller["verificationMethod"][0],
                "publicKeyMultibase": _multibase(
                    ed25519.Ed25519PrivateKey.from_private_bytes(SECOND_SEED)
                ),
            }
        ],
    }


def _build() -> dict:
    primary_key = ed25519.Ed25519PrivateKey.from_private_bytes(SEED)
    signer = LocalEd25519Signer(primary_key, key_id=KEY_ID)
    controller = build_caller_controller(caller=CALLER, signer=signer)

    headers = sign_agent_web_request(
        method=REQUEST["method"],
        target_uri=REQUEST["targetUri"],
        body=b64decode(REQUEST["bodyBase64"]),
        content_type=REQUEST["contentType"],
        caller=CALLER,
        signer=signer,
        created=CREATED,
        expires=EXPIRES,
        nonce=NONCE,
    )

    expected = {
        "content-digest": headers["Content-Digest"],
        "content-type": headers["Content-Type"],
        CALLER_HEADER.lower(): headers[CALLER_HEADER],
        "signature-input": headers["Signature-Input"],
        "signature": headers["Signature"],
    }

    def negative(name: str, expected_error: str, **overrides: object) -> dict:
        case: dict[str, object] = {"name": name, "expectedError": expected_error}
        case.update(overrides)
        return case

    return {
        "profile": "urn:agent-web:http-signature-conformance:0.1",
        "description": (
            "Byte-stable vectors for the strict Agent Web RFC 9421 profile. "
            "The Ed25519 seed is a project-fixed public test key committed "
            "here on purpose; every implementation must derive the identical "
            "public key from seedHex."
        ),
        "fixed": {
            "created": CREATED,
            "expires": EXPIRES,
            "nonce": NONCE,
            "now": CREATED,
        },
        "key": {
            "seedHex": SEED.hex(),
            "publicKeyMultibase": _multibase(primary_key),
            "secondSeedHex": SECOND_SEED.hex(),
            "keyId": KEY_ID,
        },
        "callerController": controller,
        "request": REQUEST,
        "expectedHeaders": expected,
        "negatives": [
            negative(
                "tampered-body",
                "Content-Digest does not match the request body",
                bodyBase64=b64encode(b'{"topic":"forged"}').decode("ascii"),
            ),
            negative(
                "wrong-method",
                "HTTP message signature is invalid",
                method="PUT",
            ),
            negative(
                "wrong-target-uri",
                "HTTP message signature is invalid",
                targetUri=REQUEST["targetUri"] + "?redirected=true",
            ),
            negative(
                "swapped-caller-header",
                "caller does not match its controller document",
                headers={CALLER_HEADER.lower(): "https://attacker.example/caller"},
            ),
            negative(
                "expired-signature",
                "signature has expired",
                verifyNow=EXPIRES + 31,
            ),
            negative(
                "created-in-the-future",
                "signature was created in the future",
                verifyNow=CREATED - 3600,
            ),
            negative(
                "unauthorized-authentication-key",
                "signature key is not authorized for authentication",
                controllerDocument={
                    **controller,
                    "authentication": [f"{CALLER}#other-key"],
                },
            ),
            negative(
                "malformed-signature-input",
                "Signature-Input is outside the Agent Web profile",
                headers={
                    "signature-input": expected["signature-input"].replace(
                        ';alg="ed25519"', ""
                    )
                },
            ),
            negative(
                "foreign-key-signature",
                "HTTP message signature is invalid",
                controllerDocument=_second_controller(controller),
            ),
        ],
    }


def main() -> None:
    document = _build()
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    CANONICAL.parent.mkdir(parents=True, exist_ok=True)
    TYPESCRIPT_COPY.parent.mkdir(parents=True, exist_ok=True)
    CANONICAL.write_text(text, encoding="utf-8")
    TYPESCRIPT_COPY.write_text(text, encoding="utf-8")
    print(f"wrote {CANONICAL.relative_to(ROOT)}")
    print(f"wrote {TYPESCRIPT_COPY.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
