"""Agent-only publisher: JSON resources, discovery, links, actions, and proofs."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json
from typing import Any, Iterable, Mapping
from urllib.parse import quote, urlencode, urlsplit

import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from libagentweb import (
    AGENT_WEB_VERSION,
    DISCOVERY_MEDIA_TYPE,
    RESOURCE_MEDIA_TYPE,
    build_discovery_document,
    empty_affordances,
    http_action,
    HTTP_SIGNATURE_SECURITY,
    HttpMessageSignatureError,
    HttpSignatureReplayStore,
    sign_resource,
    verify_agent_web_request,
)

from .store import KnowledgeStore


DEFAULT_TOPICS = (
    {
        "slug": "agent-web",
        "title": "Agent Web",
        "summary": "A machine-native Web of linked resources and services.",
        "body": "Agents publish, discover, verify, navigate, and act without requiring an HTML projection.",
    },
    {
        "slug": "typed-links",
        "title": "Typed links",
        "summary": "Relations make unfamiliar resources navigable.",
        "body": "Agent browsers follow declared relations under explicit trust, origin, and traversal policy.",
    },
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def create_app(
    *,
    database: str | Path = ":memory:",
    base_url: str = "https://native.example",
    private_key: ed25519.Ed25519PrivateKey | None = None,
    seed_topics: Iterable[Mapping[str, str]] = DEFAULT_TOPICS,
    caller_controllers: Mapping[str, Mapping[str, Any]] | None = None,
    annotation_writers: Iterable[str] = (),
    replay_database: str | Path = ":memory:",
) -> FastAPI:
    """Create a native Agent Web publisher with deliberately no HTML routes."""

    base_url = base_url.rstrip("/")
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("base_url must be an absolute HTTPS origin")
    key = private_key or ed25519.Ed25519PrivateKey.generate()
    publisher = f"{base_url}/.well-known/agent-web"
    method = f"{publisher}#key-1"
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    store = KnowledgeStore(database)
    replay_store = HttpSignatureReplayStore(replay_database)
    trusted_callers = {
        str(controller): dict(document)
        for controller, document in (caller_controllers or {}).items()
    }
    writers = frozenset(str(value) for value in annotation_writers)
    if not writers.issubset(trusted_callers):
        raise ValueError("every annotation writer requires a trusted controller document")
    store.seed(seed_topics)
    discovery = build_discovery_document(
        base_url=base_url,
        entry_point=f"{base_url}/resources/index",
        publisher=publisher,
        verification_methods=[
            {
                "id": method,
                "type": "Multikey",
                "controller": publisher,
                "publicKeyMultibase": "z" + base58.b58encode(b"\xed\x01" + public).decode("ascii"),
            }
        ],
        assertion_methods=[method],
        name="Native Knowledge",
        description="An agent-only knowledge site with no World Wide Web projection.",
    )

    app = FastAPI(title="Native Knowledge Agent Web Site", docs_url=None, redoc_url=None)

    def signed(document: dict[str, Any]) -> dict[str, Any]:
        return sign_resource(
            document,
            private_key=key,
            publisher=publisher,
            verification_method=method,
        )

    def resource_base(
        *, resource_id: str, resource_type: list[str], kind: str, name: str,
        description: str, links: list[dict[str, Any]], data: Any,
        affordances: dict[str, Any] | None = None, updated_at: str | None = None,
    ) -> dict[str, Any]:
        timestamp = updated_at or _now()
        return signed({
            "@context": "urn:agent-web:context:0.2",
            "@id": resource_id,
            "@type": resource_type,
            "agentWeb": {"version": AGENT_WEB_VERSION, "kind": kind},
            "name": name,
            "description": description,
            "links": links,
            "affordances": affordances or empty_affordances(),
            "provenance": {
                "publisher": publisher,
                "createdAt": timestamp,
                "updatedAt": timestamp,
                "canonical": resource_id,
            },
            "data": data,
        })

    def collection_resource() -> dict[str, Any]:
        resource_id = f"{base_url}/resources/index"
        topics = store.topics()
        affordances = empty_affordances()
        affordances["actions"]["search"] = http_action(
            description="Search this native Agent Web site.",
            url=f"{base_url}/resources/search",
            method="GET",
            input_schema={
                "type": "object",
                "required": ["q"],
                "additionalProperties": False,
                "properties": {
                    "q": {"type": "string", "minLength": 1, "maxLength": 200},
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "default": 20,
                    },
                },
            },
            output_schema={"$ref": "urn:agent-web:schema:resource:0.2"},
            safe=True,
            idempotent=True,
            authorization_level="normal",
        )
        if writers:
            affordances["actions"]["createAnnotation"] = http_action(
                description="Publish an authenticated annotation on a knowledge topic.",
                url=f"{base_url}/actions/annotations",
                method="POST",
                input_schema={
                    "type": "object",
                    "required": ["topic", "text"],
                    "additionalProperties": False,
                    "properties": {
                        "topic": {
                            "type": "string",
                            "pattern": "^[a-z0-9]+(?:-[a-z0-9]+)*$",
                            "maxLength": 100,
                        },
                        "text": {"type": "string", "minLength": 1, "maxLength": 4000},
                    },
                },
                output_schema={"$ref": "urn:agent-web:schema:resource:0.2"},
                safe=False,
                idempotent=False,
                authorization_level="normal",
                security=HTTP_SIGNATURE_SECURITY,
            )
        links = [{"rel": "self", "href": resource_id, "mediaType": RESOURCE_MEDIA_TYPE}]
        links.extend({
            "rel": "item",
            "href": f"{base_url}/resources/topics/{quote(topic['slug'], safe='')}",
            "mediaType": RESOURCE_MEDIA_TYPE,
            "title": topic["title"],
        } for topic in topics)
        links.extend({
            "rel": "item",
            "href": f"{base_url}/resources/annotations/{item['annotation_id']}",
            "mediaType": RESOURCE_MEDIA_TYPE,
            "title": f"Annotation on {item['topic_slug']}",
        } for item in store.annotations())
        return resource_base(
            resource_id=resource_id,
            resource_type=["AgentWebCollection", "KnowledgeIndex"],
            kind="collection",
            name="Native Knowledge",
            description="Knowledge published directly on Agent Web for agent browsers.",
            links=links,
            affordances=affordances,
            data={
                "topicCount": len(topics),
                "annotationCount": len(store.annotations()),
                "humanView": None,
                "anpRequired": False,
            },
        )

    def annotation_resource(record: Mapping[str, Any]) -> dict[str, Any]:
        resource_id = f"{base_url}/resources/annotations/{record['annotation_id']}"
        topic_url = f"{base_url}/resources/topics/{quote(str(record['topic_slug']), safe='')}"
        return resource_base(
            resource_id=resource_id,
            resource_type=["AgentWebResource", "KnowledgeAnnotation"],
            kind="resource",
            name=f"Annotation on {record['topic_slug']}",
            description="An authenticated Agent Web caller annotation.",
            links=[
                {"rel": "self", "href": resource_id, "mediaType": RESOURCE_MEDIA_TYPE},
                {"rel": "about", "href": topic_url, "mediaType": RESOURCE_MEDIA_TYPE},
                {"rel": "collection", "href": f"{base_url}/resources/index", "mediaType": RESOURCE_MEDIA_TYPE},
            ],
            data={
                "topic": record["topic_slug"],
                "text": record["text"],
                "author": record["author"],
            },
            updated_at=str(record["created_at"]),
        )

    @app.middleware("http")
    async def secure_machine_surface(request: Request, call_next: Any) -> Any:
        if request.url.scheme != "https":
            return JSONResponse(status_code=400, content={"detail": "HTTPS is required"})
        if request.headers.get("host", "").lower() != parsed.netloc.lower():
            return JSONResponse(
                status_code=421,
                content={"detail": "request authority is not configured"},
            )
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/.well-known/agent-web")
    async def discover() -> JSONResponse:
        return JSONResponse(discovery, media_type=DISCOVERY_MEDIA_TYPE)

    @app.get("/agent-web/0.2")
    async def profile() -> JSONResponse:
        return JSONResponse({
            "name": "Agent Web Resource Profile",
            "version": AGENT_WEB_VERSION,
            "resourceMediaType": RESOURCE_MEDIA_TYPE,
        })

    @app.get("/resources/index")
    async def index() -> JSONResponse:
        return JSONResponse(collection_resource(), media_type=RESOURCE_MEDIA_TYPE)

    @app.get("/resources/topics/{slug}")
    async def topic(slug: str) -> JSONResponse:
        record = store.topic(slug)
        if record is None:
            raise HTTPException(404, "topic not found")
        resource_id = f"{base_url}/resources/topics/{quote(slug, safe='')}"
        return JSONResponse(resource_base(
            resource_id=resource_id,
            resource_type=["AgentWebResource", "KnowledgeTopic"],
            kind="resource",
            name=record["title"],
            description=record["summary"],
            links=[
                {"rel": "self", "href": resource_id, "mediaType": RESOURCE_MEDIA_TYPE},
                {"rel": "collection", "href": f"{base_url}/resources/index", "mediaType": RESOURCE_MEDIA_TYPE},
            ],
            data={"body": record["body"]},
            updated_at=record["updated_at"],
        ), media_type=RESOURCE_MEDIA_TYPE)

    @app.get("/resources/search")
    async def search(q: str = Query(min_length=1, max_length=200), limit: int = Query(20, ge=1, le=100)) -> JSONResponse:
        records = store.search(q, limit=limit)
        resource_id = f"{base_url}/resources/search?{urlencode({'q': q, 'limit': limit})}"
        links = [
            {"rel": "self", "href": resource_id, "mediaType": RESOURCE_MEDIA_TYPE},
            {"rel": "collection", "href": f"{base_url}/resources/index", "mediaType": RESOURCE_MEDIA_TYPE},
        ]
        links.extend({
            "rel": "item",
            "href": f"{base_url}/resources/topics/{quote(record['slug'], safe='')}",
            "mediaType": RESOURCE_MEDIA_TYPE,
            "title": record["title"],
        } for record in records)
        return JSONResponse(resource_base(
            resource_id=resource_id,
            resource_type=["AgentWebCollection", "SearchResults"],
            kind="collection",
            name=f"Native Knowledge search: {q}",
            description="Agent-native search results.",
            links=links,
            data={"query": q, "count": len(records)},
        ), media_type=RESOURCE_MEDIA_TYPE)

    @app.post("/actions/annotations")
    async def create_annotation(request: Request) -> JSONResponse:
        body = await request.body()
        if len(body) > 16 * 1024:
            raise HTTPException(413, "request body is too large")
        caller = request.headers.get("agent-web-caller", "")
        controller = trusted_callers.get(caller)
        if controller is None:
            raise HTTPException(401, "authenticated Agent Web caller is required")
        try:
            authenticated = verify_agent_web_request(
                method=request.method,
                target_uri=(
                    f"{base_url}{request.url.path}"
                    + (f"?{request.url.query}" if request.url.query else "")
                ),
                body=body,
                headers=request.headers,
                raw_headers=request.scope.get("headers", ()),
                controller_document=controller,
                replay_store=replay_store,
            )
        except (HttpMessageSignatureError, ValueError) as exc:
            raise HTTPException(401, str(exc)) from exc
        if authenticated.controller not in writers:
            raise HTTPException(403, "caller is not authorized to create annotations")
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(400, "request body must be a JSON object") from exc
        if not isinstance(payload, dict) or set(payload) != {"topic", "text"}:
            raise HTTPException(422, "annotation requires exactly topic and text")
        if not isinstance(payload["topic"], str) or not isinstance(payload["text"], str):
            raise HTTPException(422, "annotation topic and text must be strings")
        try:
            record = store.create_annotation(
                topic_slug=payload["topic"],
                author=authenticated.controller,
                text=payload["text"],
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return JSONResponse(
            annotation_resource(record),
            status_code=201,
            media_type=RESOURCE_MEDIA_TYPE,
        )

    @app.get("/resources/annotations/{annotation_id}")
    async def annotation(annotation_id: str) -> JSONResponse:
        record = store.annotation(annotation_id)
        if record is None:
            raise HTTPException(404, "annotation not found")
        return JSONResponse(annotation_resource(record), media_type=RESOURCE_MEDIA_TYPE)

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "publisher": publisher, "database": store.integrity_check()}

    @app.get("/ready")
    async def ready() -> JSONResponse:
        healthy = store.integrity_check()
        return JSONResponse(
            {"status": "ready" if healthy else "not-ready", "database": healthy},
            status_code=200 if healthy else 503,
        )

    app.state.knowledge_store = store
    app.state.publisher = publisher

    def close() -> None:
        replay_store.close()
        store.close()

    app.state.replay_store = replay_store
    app.state.close = close
    return app
