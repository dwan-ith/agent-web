"""Agent Web resource construction, validation, and link traversal."""

from __future__ import annotations

from collections import deque
from copy import deepcopy
from datetime import datetime, timezone
from importlib.resources import files
import json
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from jsonschema import Draft202012Validator, FormatChecker


AGENT_WEB_VERSION = "0.2"
RESOURCE_MEDIA_TYPE = "application/agent-web+json"


class ResourceValidationError(ValueError):
    """An Agent Web document does not conform to the resource profile."""


def load_resource_schema(path: str | Path | None = None) -> dict[str, Any]:
    """Load the packaged schema, or an explicitly supplied schema file."""

    if path is not None:
        with Path(path).open(encoding="utf-8") as handle:
            return json.load(handle)
    schema = files("libagentweb.schemas").joinpath(
        "agent-web-resource.schema.json"
    )
    return json.loads(schema.read_text(encoding="utf-8"))


def load_context() -> dict[str, Any]:
    """Load the packaged JSON-LD context."""

    context = files("libagentweb.schemas").joinpath(
        "agent-web-context.jsonld"
    )
    return json.loads(context.read_text(encoding="utf-8"))


_VALIDATOR = Draft202012Validator(
    load_resource_schema(),
    format_checker=FormatChecker(),
)


def validate_resource(document: Mapping[str, Any]) -> dict[str, Any]:
    errors = sorted(_VALIDATOR.iter_errors(document), key=lambda error: list(error.path))
    if errors:
        details = "; ".join(
            f"{'/'.join(map(str, error.absolute_path)) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ResourceValidationError(details)

    resource = deepcopy(dict(document))
    if resource["provenance"]["canonical"] != resource["@id"]:
        raise ResourceValidationError(
            "provenance/canonical: must exactly match @id"
        )
    if resource["provenance"]["publisher"] != _proof_issuer(resource):
        raise ResourceValidationError(
            "proof/verificationMethod: must belong to provenance.publisher"
        )

    created = _parse_timestamp(resource["provenance"]["createdAt"], "createdAt")
    updated = _parse_timestamp(resource["provenance"]["updatedAt"], "updatedAt")
    if updated < created:
        raise ResourceValidationError(
            "provenance/updatedAt: must not precede createdAt"
        )
    expires_at = resource["provenance"].get("expiresAt")
    if expires_at is not None and _parse_timestamp(expires_at, "expiresAt") <= updated:
        raise ResourceValidationError(
            "provenance/expiresAt: must be later than updatedAt"
        )
    return resource


def is_resource_expired(
    document: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> bool:
    """Return whether a validated resource is outside its advertised lifetime."""

    resource = validate_resource(document)
    expires_at = resource["provenance"].get("expiresAt")
    if expires_at is None:
        return False
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    return _parse_timestamp(expires_at, "expiresAt") <= current


def links_by_rel(
    document: Mapping[str, Any],
    rel: str,
) -> list[dict[str, Any]]:
    return [
        deepcopy(link)
        for link in document.get("links", [])
        if isinstance(link, Mapping) and link.get("rel") == rel
    ]


def walk_linked_resources(
    entrypoint: str,
    fetch: Callable[[str], Mapping[str, Any]],
    *,
    rels: Iterable[str] = ("item", "next", "related"),
    max_resources: int = 100,
) -> list[dict[str, Any]]:
    """Traverse selected typed links without assuming application-specific fields."""

    allowed = set(rels)
    queue = deque([entrypoint])
    visited: set[str] = set()
    result: list[dict[str, Any]] = []

    while queue:
        target = queue.popleft()
        if target in visited:
            continue
        if len(visited) >= max_resources:
            raise RuntimeError("Agent Web traversal exceeded its resource limit")
        visited.add(target)

        document = validate_resource(fetch(target))
        result.append(document)
        for link in document["links"]:
            if link["rel"] in allowed and link["href"] not in visited:
                queue.append(link["href"])
    return result


def empty_affordances() -> dict[str, dict[str, Any]]:
    return {"properties": {}, "actions": {}, "events": {}}


def anp_action(
    *,
    description: str,
    rpc_url: str,
    method: str,
    input_schema: Mapping[str, Any],
    output_schema: Mapping[str, Any],
    safe: bool,
    idempotent: bool,
    authorization_level: str,
) -> dict[str, Any]:
    if authorization_level not in {"normal", "user-presence-required"}:
        raise ValueError("authorization_level is not recognized")
    return {
        "description": description,
        "input": deepcopy(dict(input_schema)),
        "output": deepcopy(dict(output_schema)),
        "safe": safe,
        "idempotent": idempotent,
        "authorizationLevel": authorization_level,
        "interfaces": [
            {
                "protocol": "ANP",
                "href": rpc_url,
                "method": method,
                "contentType": "application/json",
            }
        ],
    }


def _proof_issuer(document: Mapping[str, Any]) -> str:
    method = str(document["proof"]["verificationMethod"])
    return method.split("#", 1)[0]


def _parse_timestamp(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ResourceValidationError(
            f"provenance/{field}: invalid RFC3339 timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise ResourceValidationError(
            f"provenance/{field}: timestamp must include a timezone"
        )
    return parsed
