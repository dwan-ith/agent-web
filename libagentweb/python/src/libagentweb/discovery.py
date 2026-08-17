"""Web-native Agent Web discovery documents."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from .resource import AGENT_WEB_VERSION, RESOURCE_MEDIA_TYPE


DISCOVERY_PATH = "/.well-known/agent-web"
DISCOVERY_MEDIA_TYPE = "application/agent-web-discovery+json"


class DiscoveryValidationError(ValueError):
    """A Web-native discovery document is incomplete or unsafe."""


def build_discovery_document(
    *,
    base_url: str,
    entry_point: str,
    publisher: str,
    verification_methods: Sequence[Mapping[str, Any]],
    assertion_methods: Sequence[str] | None = None,
    human_view: str | None = None,
    name: str | None = None,
    description: str | None = None,
) -> dict[str, Any]:
    """Build an origin-bound discovery and proof-controller document."""

    root = base_url.rstrip("/")
    document: dict[str, Any] = {
        "id": publisher,
        "publisher": publisher,
        "agentWeb": {
            "version": AGENT_WEB_VERSION,
            "profile": f"{root}/agent-web/{AGENT_WEB_VERSION}",
            "entryPoint": entry_point,
            "resourceMediaType": RESOURCE_MEDIA_TYPE,
        },
        "verificationMethod": [deepcopy(dict(item)) for item in verification_methods],
        "assertionMethod": list(assertion_methods or ()),
    }
    if human_view is not None:
        document["agentWeb"]["humanView"] = human_view
    if name is not None:
        document["name"] = name
    if description is not None:
        document["description"] = description
    if not document["assertionMethod"]:
        document["assertionMethod"] = [
            item["id"]
            for item in document["verificationMethod"]
            if isinstance(item.get("id"), str)
        ]
    return validate_discovery_document(
        document,
        discovery_url=f"{root}{DISCOVERY_PATH}",
    )


def validate_discovery_document(
    document: Mapping[str, Any],
    *,
    discovery_url: str,
) -> dict[str, Any]:
    """Validate discovery using ordinary HTTPS origin authority."""

    result = deepcopy(dict(document))
    discovery_origin = _origin(discovery_url)
    publisher = result.get("publisher")
    if not isinstance(publisher, str) or not (
        publisher.startswith("https://")
        or publisher.startswith("did:web:")
        or publisher.startswith("did:wba:")
    ):
        raise DiscoveryValidationError("publisher must be HTTPS, did:web, or did:wba")
    if result.get("id") != publisher:
        raise DiscoveryValidationError("discovery id must equal publisher")
    profile = result.get("agentWeb")
    if not isinstance(profile, Mapping) or profile.get("version") != AGENT_WEB_VERSION:
        raise DiscoveryValidationError("unsupported Agent Web discovery version")
    for field in ("profile", "entryPoint"):
        value = profile.get(field)
        if not isinstance(value, str) or _origin(value) != discovery_origin:
            raise DiscoveryValidationError(f"{field} must use the discovery origin")
    if profile.get("resourceMediaType") != RESOURCE_MEDIA_TYPE:
        raise DiscoveryValidationError("unexpected Agent Web resource media type")
    human_view = profile.get("humanView")
    if human_view is not None and (
        not isinstance(human_view, str) or _origin(human_view) != discovery_origin
    ):
        raise DiscoveryValidationError("humanView must use the discovery origin")
    for field, limit in (("name", 300), ("description", 4000)):
        value = result.get(field)
        if value is not None and (
            not isinstance(value, str) or not value.strip() or len(value) > limit
        ):
            raise DiscoveryValidationError(f"{field} is invalid")
    methods = result.get("verificationMethod")
    assertions = result.get("assertionMethod")
    if not isinstance(methods, list) or not methods:
        raise DiscoveryValidationError("discovery has no verification methods")
    if not isinstance(assertions, list) or not assertions:
        raise DiscoveryValidationError("discovery has no assertion methods")
    method_ids: set[str] = set()
    for method in methods:
        if not isinstance(method, Mapping):
            raise DiscoveryValidationError("verification methods must be objects")
        method_id = method.get("id")
        if not isinstance(method_id, str) or not method_id.startswith(f"{publisher}#"):
            raise DiscoveryValidationError("verification method does not belong to publisher")
        if method_id in method_ids:
            raise DiscoveryValidationError("duplicate verification method")
        method_ids.add(method_id)
    if any(item not in method_ids for item in assertions if isinstance(item, str)):
        raise DiscoveryValidationError("assertion method is not published")
    if not all(isinstance(item, str) for item in assertions):
        raise DiscoveryValidationError("assertion methods must be identifiers")
    return result


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise DiscoveryValidationError("Agent Web discovery requires absolute HTTPS URLs")
    port = parsed.port
    authority = parsed.hostname.lower()
    if port is not None and port != 443:
        authority = f"{authority}:{port}"
    return f"https://{authority}"
