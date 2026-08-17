"""Protocol-neutral signing and verification for Agent Web documents."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .network import request_json
from .resource import (
    ResourceValidationError,
    is_resource_expired,
    validate_resource,
)
from .signing import LocalEd25519Signer, sign_object_proof, verify_object_proof


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
    publisher_did: str | None = None,
    publisher: str | None = None,
    verification_method: str | None = None,
) -> dict[str, Any]:
    """Sign a resource after binding its provenance to its publisher.

    ``publisher_did`` remains supported for existing ANP adapters.  New
    Web-native publishers should use ``publisher`` with an absolute HTTPS
    controller URL.
    """

    unsigned = deepcopy(dict(document))
    unsigned.pop("proof", None)
    provenance = unsigned.get("provenance")
    if not isinstance(provenance, dict):
        raise ResourceValidationError("provenance: must be an object")
    controller = publisher or publisher_did
    if controller is None:
        raise ValueError("publisher is required")
    if publisher is not None and publisher_did is not None and publisher != publisher_did:
        raise ValueError("publisher and publisher_did disagree")
    if provenance.get("publisher") != controller:
        raise ResourceTrustError(
            "resource publisher does not match the signing controller"
        )
    method = verification_method or f"{controller}#key-1"
    signed = sign_object_proof(
        unsigned,
        signer=LocalEd25519Signer(private_key, key_id=method),
        issuer_did=controller,
        verification_method=method,
    )
    return validate_resource(signed)


def verify_resource(
    document: Mapping[str, Any],
    *,
    publisher_did_document: Mapping[str, Any] | None = None,
    controller_document: Mapping[str, Any] | None = None,
    reject_expired: bool = True,
) -> dict[str, Any]:
    """Validate a resource and verify its proof against a controller document."""

    resource = validate_resource(document)
    publisher = resource["provenance"]["publisher"]
    controller = controller_document or publisher_did_document
    if controller is None:
        raise ValueError("controller_document is required")
    try:
        verify_object_proof(
            resource,
            issuer=publisher,
            controller_document=deepcopy(dict(controller)),
        )
    except ValueError as exc:
        raise ResourceTrustError(str(exc)) from exc
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
    """Resolve a publisher controller and verify a resource.

    HTTPS publisher controllers are the Agent Web core path. ``did:web`` is
    resolved directly over HTTPS. ``did:wba`` is retained through a lazy ANP
    compatibility import and is not required to install or use the core.
    """

    resource = validate_resource(document)
    publisher = resource["provenance"]["publisher"]
    try:
        if publisher.startswith("https://"):
            controller = (
                await request_json(publisher, headers={"Accept": "application/json"})
            ).document
        elif publisher.startswith("did:web:"):
            controller = (
                await request_json(
                    _did_web_resolution_url(publisher),
                    headers={"Accept": "application/did+ld+json, application/json"},
                )
            ).document
        elif publisher.startswith("did:wba:"):
            try:
                from anp.authentication import resolve_did_document
            except ModuleNotFoundError as exc:
                raise ResourceTrustError(
                    "did:wba resolution requires the optional libagentweb[anp] adapter"
                ) from exc
            controller = await resolve_did_document(publisher, verify_proof=True)
        else:
            raise ResourceTrustError("unsupported publisher controller")
    except Exception as exc:
        if isinstance(exc, ResourceTrustError):
            raise
        raise ResourceTrustError(
            f"could not securely resolve publisher {publisher}: {exc}"
        ) from exc
    return verify_resource(
        resource,
        controller_document=controller,
        reject_expired=reject_expired,
    )


def _did_web_resolution_url(did: str) -> str:
    """Resolve the HTTPS URL defined by the did:web method."""

    segments = did.split(":")
    if len(segments) < 3 or segments[:2] != ["did", "web"]:
        raise ValueError("not a did:web identifier")
    from urllib.parse import unquote

    authority = unquote(segments[2])
    if not authority or "/" in authority or "@" in authority:
        raise ValueError("invalid did:web authority")
    if len(segments) == 3:
        return f"https://{authority}/.well-known/did.json"
    path = "/".join(unquote(item) for item in segments[3:])
    if any(item in {"", ".", ".."} for item in path.split("/")):
        raise ValueError("invalid did:web path")
    return f"https://{authority}/{path}/did.json"
