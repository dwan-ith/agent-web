"""DID-WBA-backed signing and verification for Agent Web documents."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from anp.authentication import resolve_did_document
from anp.proof.object_proof import (
    ObjectProofError,
    generate_object_proof,
    verify_object_proof,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .resource import (
    ResourceValidationError,
    is_resource_expired,
    validate_resource,
)


class ResourceTrustError(ValueError):
    """A resource is structurally valid but its publisher cannot be trusted."""


def load_ed25519_private_key(
    private_key_path: str | Path,
) -> ed25519.Ed25519PrivateKey:
    """Load an unencrypted Ed25519 PEM key from an operator-controlled path."""

    value = serialization.load_pem_private_key(
        Path(private_key_path).read_bytes(),
        password=None,
    )
    if not isinstance(value, ed25519.Ed25519PrivateKey):
        raise TypeError("Agent Web object proofs require an Ed25519 private key")
    return value


def sign_resource(
    document: Mapping[str, Any],
    *,
    private_key: ed25519.Ed25519PrivateKey,
    publisher_did: str,
    verification_method: str | None = None,
) -> dict[str, Any]:
    """Sign a resource after binding its provenance to the signing DID."""

    unsigned = deepcopy(dict(document))
    unsigned.pop("proof", None)
    provenance = unsigned.get("provenance")
    if not isinstance(provenance, dict):
        raise ResourceValidationError("provenance: must be an object")
    if provenance.get("publisher") != publisher_did:
        raise ResourceTrustError(
            "resource publisher does not match the signing DID"
        )
    method = verification_method or f"{publisher_did}#key-1"
    signed = generate_object_proof(
        unsigned,
        private_key,
        method,
        issuer_did=publisher_did,
    )
    return validate_resource(signed)


def verify_resource(
    document: Mapping[str, Any],
    *,
    publisher_did_document: Mapping[str, Any],
    reject_expired: bool = True,
) -> dict[str, Any]:
    """Validate a resource and verify its object proof against its DID document."""

    resource = validate_resource(document)
    publisher = resource["provenance"]["publisher"]
    try:
        verify_object_proof(
            resource,
            issuer_did=publisher,
            issuer_did_document=deepcopy(dict(publisher_did_document)),
        )
    except ObjectProofError as exc:
        raise ResourceTrustError(f"{exc.code}: {exc}") from exc
    proof_created = datetime.fromisoformat(
        resource["proof"]["created"].replace("Z", "+00:00")
    )
    if proof_created > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise ResourceTrustError("resource proof was created too far in the future")
    if reject_expired and is_resource_expired(resource):
        raise ResourceTrustError("resource has expired")
    return resource


async def resolve_and_verify_resource(
    document: Mapping[str, Any],
    *,
    reject_expired: bool = True,
) -> dict[str, Any]:
    """Resolve the publisher DID-WBA document and verify a resource."""

    resource = validate_resource(document)
    publisher = resource["provenance"]["publisher"]
    try:
        did_document = await resolve_did_document(
            publisher,
            verify_proof=True,
        )
    except Exception as exc:
        raise ResourceTrustError(
            f"could not securely resolve publisher DID {publisher}: {exc}"
        ) from exc
    return verify_resource(
        resource,
        publisher_did_document=did_document,
        reject_expired=reject_expired,
    )
