"""Shared profile endpoints and HTTP representation helpers."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from libagentweb.resource import (
    AGENT_WEB_VERSION,
    RESOURCE_MEDIA_TYPE,
    load_context,
    load_resource_schema,
    validate_resource,
)


def mount_agent_web_profile(app: FastAPI, base_url: str) -> None:
    """Publish the shared Agent Web profile from any conforming site."""

    root = base_url.rstrip("/")

    @app.get("/agent-web/0.2")
    async def profile() -> dict[str, Any]:
        return {
            "name": "Agent Web Resource Profile",
            "version": AGENT_WEB_VERSION,
            "schema": f"{root}/agent-web/0.2/schema.json",
            "context": f"{root}/agent-web/0.2/context.jsonld",
            "transport": "Agent Network Protocol",
        }

    @app.get("/agent-web/0.2/schema.json")
    async def schema() -> JSONResponse:
        return JSONResponse(load_resource_schema())

    @app.get("/agent-web/0.2/context.jsonld")
    async def context() -> JSONResponse:
        return JSONResponse(load_context(), media_type="application/ld+json")


def resource_response(document: dict[str, Any]) -> JSONResponse:
    """Validate at the publisher boundary and emit the Agent Web media type."""

    return JSONResponse(
        validate_resource(document),
        media_type=RESOURCE_MEDIA_TYPE,
    )
