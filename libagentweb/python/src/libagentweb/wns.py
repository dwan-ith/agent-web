"""High-assurance WNS resolution for Agent Web browsers."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping
from urllib.parse import urlsplit

from anp.authentication.did_resolver import build_did_resolution_url
from anp.authentication.did_wba import validate_did_document_binding
from anp.wns import (
    HandleValidationError,
    HandleResolutionDocument,
    HandleStatus,
    build_resolution_url,
    compare_binding_generations,
    normalize_handle,
    validate_handle,
)
from .network import request_json


DocumentFetcher = Callable[[str], Awaitable[Mapping[str, Any]]]
DidResolver = Callable[[str], Awaitable[Mapping[str, Any]]]


class HandleTrustError(ValueError):
    """A WNS response failed exact-handle verification."""


@dataclass(frozen=True, slots=True)
class ResolvedHandle:
    """An exact Handle-to-DID binding with its verified DID document."""

    handle: str
    did: str
    binding_generation: str
    resolution_url: str
    did_document: dict[str, Any]


async def resolve_exact_handle(
    handle: str,
    *,
    timeout: float = 8.0,
    max_response_bytes: int = 256 * 1024,
    minimum_binding_generation: str | None = None,
    allow_private_networks: bool = False,
    fetch_document: DocumentFetcher | None = None,
    did_resolver: DidResolver | None = None,
) -> ResolvedHandle:
    """Resolve WNS and require an exact, proof-verified reverse binding.

    Provider-domain confirmation is deliberately insufficient here. The DID
    document must point back to this handle's canonical well-known endpoint.
    """

    try:
        normalized = normalize_handle(
            handle[len("wba://") :] if handle.startswith("wba://") else handle
        )
        local_part, domain = validate_handle(normalized)
    except HandleValidationError as exc:
        raise HandleTrustError(f"invalid WNS handle: {exc}") from exc
    resolution_url = build_resolution_url(local_part, domain)

    if fetch_document is None:
        async def default_fetch(url: str) -> Mapping[str, Any]:
            return await _get_json(
                url,
                timeout=timeout,
                max_response_bytes=max_response_bytes,
                allow_private_networks=allow_private_networks,
            )

        fetch_document = default_fetch
    if did_resolver is None:
        async def default_did_resolver(did: str) -> Mapping[str, Any]:
            response = await request_json(
                build_did_resolution_url(did),
                headers={"Accept": "application/did+json, application/json"},
                timeout=timeout,
                max_response_bytes=max_response_bytes,
                allow_private_networks=allow_private_networks,
            )
            if response.status != 200:
                raise HandleTrustError(
                    f"WNS DID endpoint returned HTTP {response.status}"
                )
            if not validate_did_document_binding(
                response.document,
                verify_proof=True,
            ):
                raise HandleTrustError("WNS DID has an invalid proof or key binding")
            return response.document

        did_resolver = default_did_resolver

    try:
        resolution = HandleResolutionDocument.model_validate(
            dict(await fetch_document(resolution_url))
        )
    except Exception as exc:
        raise HandleTrustError(f"WNS resolution document is invalid: {exc}") from exc
    if normalize_handle(resolution.handle) != normalized:
        raise HandleTrustError("WNS response handle does not match the request")
    if resolution.status != HandleStatus.ACTIVE:
        raise HandleTrustError(
            f"WNS handle is not active: {resolution.status.value}"
        )
    if _did_wba_hostname(resolution.did) != domain:
        raise HandleTrustError("WNS handle domain does not match the DID hostname")
    if minimum_binding_generation is not None and compare_binding_generations(
        resolution.binding_generation,
        minimum_binding_generation,
    ) < 0:
        raise HandleTrustError("WNS binding generation is older than the trusted floor")

    try:
        did_document = dict(await did_resolver(resolution.did))
    except Exception as exc:
        raise HandleTrustError(f"WNS DID proof resolution failed: {exc}") from exc
    if did_document.get("id") != resolution.did:
        raise HandleTrustError("resolved DID document id does not match the WNS DID")
    services = did_document.get("service", [])
    exact = [
        service
        for service in services
        if isinstance(service, Mapping)
        and service.get("type") == "ANPHandleService"
        and service.get("serviceEndpoint") == resolution_url
    ]
    if not exact:
        raise HandleTrustError(
            "DID document does not declare this exact canonical handle endpoint"
        )
    if len(exact) > 1:
        raise HandleTrustError("DID document contains duplicate exact handle services")
    if exact[0].get("id") != f"{resolution.did}#handle":
        raise HandleTrustError("exact handle service has a non-canonical id")

    return ResolvedHandle(
        handle=normalized,
        did=resolution.did,
        binding_generation=resolution.binding_generation,
        resolution_url=resolution_url,
        did_document=deepcopy(did_document),
    )


async def _get_json(
    url: str,
    *,
    timeout: float,
    max_response_bytes: int,
    allow_private_networks: bool,
) -> dict[str, Any]:
    response = await request_json(
        url,
        headers={"Accept": "application/json"},
        timeout=timeout,
        max_response_bytes=max_response_bytes,
        allow_private_networks=allow_private_networks,
    )
    if response.status != 200:
        raise HandleTrustError(f"WNS endpoint returned HTTP {response.status}")
    return response.document


def _did_wba_hostname(did: str) -> str:
    if not isinstance(did, str) or not did.startswith("did:wba:"):
        raise HandleTrustError("WNS resolved a non-DID-WBA identifier")
    parts = did.split(":", 3)
    if len(parts) < 4:
        raise HandleTrustError("WNS resolved a malformed DID-WBA identifier")
    from urllib.parse import unquote

    parsed = urlsplit(f"//{unquote(parts[2])}")
    if parsed.hostname is None:
        raise HandleTrustError("WNS DID-WBA identifier has no hostname")
    return parsed.hostname.lower()
