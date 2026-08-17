"""Shared profile endpoints and HTTP representation helpers."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from libagentweb.resource import (
    AGENT_WEB_VERSION,
    RESOURCE_MEDIA_TYPE,
    load_context,
    load_resource_schema,
    validate_resource,
)
from libagentweb.discovery import (
    DISCOVERY_MEDIA_TYPE,
    build_discovery_document,
)


def mount_agent_web_profile(
    app: FastAPI,
    base_url: str,
    *,
    entry_point: str | None = None,
    human_view: str | None = None,
    controller_document: Mapping[str, Any] | None = None,
) -> None:
    """Publish the Web-native profile and optional origin discovery document."""

    root = base_url.rstrip("/")

    @app.get("/agent-web/0.2")
    async def profile() -> dict[str, Any]:
        return {
            "name": "Agent Web Resource Profile",
            "version": AGENT_WEB_VERSION,
            "schema": f"{root}/agent-web/0.2/schema.json",
            "context": f"{root}/agent-web/0.2/context.jsonld",
            "transport": "HTTPS",
            "optionalBindings": ["ANP"],
        }

    @app.get("/agent-web/0.2/schema.json")
    async def schema() -> JSONResponse:
        return JSONResponse(load_resource_schema())

    @app.get("/agent-web/0.2/context.jsonld")
    async def context() -> JSONResponse:
        return JSONResponse(load_context(), media_type="application/ld+json")

    if entry_point is not None:
        if controller_document is None:
            raise ValueError("controller_document is required for Web discovery")
        publisher = controller_document.get("id")
        methods = controller_document.get("verificationMethod")
        assertions = controller_document.get("assertionMethod")
        if not isinstance(publisher, str) or not isinstance(methods, list):
            raise ValueError("controller document has no publisher verification methods")
        discovery = build_discovery_document(
            base_url=root,
            entry_point=entry_point,
            publisher=publisher,
            verification_methods=[
                deepcopy(dict(item)) for item in methods if isinstance(item, Mapping)
            ],
            assertion_methods=(
                [str(item) for item in assertions]
                if isinstance(assertions, list)
                else None
            ),
            human_view=human_view,
        )

        @app.get("/.well-known/agent-web")
        async def web_discovery() -> JSONResponse:
            return JSONResponse(discovery, media_type=DISCOVERY_MEDIA_TYPE)


def resource_response(document: dict[str, Any]) -> JSONResponse:
    """Validate at the publisher boundary and emit the Agent Web media type."""

    return JSONResponse(
        validate_resource(document),
        media_type=RESOURCE_MEDIA_TYPE,
    )
