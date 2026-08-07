"""Signed Agent Web registry/search publisher."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from agent_web_server import (
    PublisherIdentity,
    SecurityConfig,
    generate_publisher_identity,
    install_security,
    install_maintenance,
    install_observability,
    mount_agent_web_profile,
    mount_identity,
    mount_identity_handle,
    resource_response,
)
from anp.openanp import AgentConfig, Context, anp_agent, interface
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse
from libagentweb import (
    AGENT_WEB_VERSION,
    RESOURCE_MEDIA_TYPE,
    anp_action,
    empty_affordances,
    sign_resource,
)

from .store import RegistryStore


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _build_agent(
    *,
    identity: PublisherIdentity,
    store: RegistryStore,
    base_url: str,
) -> Any:
    created_at = _now()

    @anp_agent(
        AgentConfig(
            name="Agent Web Registry",
            did=identity.did,
            prefix="/registry",
            description="Verified search over independently published Agent Web resources.",
            tags=["ANP", "Agent Web", "Registry", "Search"],
        )
    )
    class RegistryAgent:
        def customize_ad(
            self,
            document: dict[str, Any],
            request_base_url: str,
        ) -> dict[str, Any]:
            document["agentWeb"] = {
                "profile": f"{base_url}/agent-web/0.2",
                "version": AGENT_WEB_VERSION,
                "entryPoint": f"{base_url}/registry/resources/index.json",
                "resourceMediaType": RESOURCE_MEDIA_TYPE,
                "humanView": f"{base_url}/directory",
            }
            document["security"] = {
                "authentication": "didwba-http-message-signatures",
                "transport": "TLS",
                "objectProof": "eddsa-jcs-2022",
                "indexAdmission": "operator-proof-verified",
            }
            return identity.sign_document(document)

        @interface(description="List proof-verified Agent Web publishers.")
        async def list_publishers(self, ctx: Context) -> dict[str, Any]:
            return self.collection_resource()

        @interface(description="Search proof-verified Agent Web resources.")
        async def search(
            self,
            query: str,
            ctx: Context,
            limit: int = 20,
        ) -> dict[str, Any]:
            return self.search_resource(query, limit)

        def collection_resource(self) -> dict[str, Any]:
            resource_id = f"{base_url}/registry/resources/index.json"
            sites = store.sites()
            affordances = empty_affordances()
            affordances["actions"]["search"] = anp_action(
                description="Search only resources admitted after proof verification.",
                rpc_url=f"{base_url}/registry/rpc",
                method="search",
                input_schema={
                    "type": "object",
                    "required": ["query"],
                    "additionalProperties": False,
                    "properties": {
                        "query": {"type": "string", "minLength": 1, "maxLength": 200},
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
            return _sign(
                identity,
                {
                    "@context": f"{base_url}/agent-web/0.2/context.jsonld",
                    "@id": resource_id,
                    "@type": ["AgentWebCollection", "AgentRegistry"],
                    "agentWeb": {"version": AGENT_WEB_VERSION, "kind": "collection"},
                    "name": "Agent Web Registry",
                    "description": (
                        "A directory of resources verified against their source "
                        "publisher DIDs and object proofs."
                    ),
                    "links": [
                        {
                            "rel": "self",
                            "href": resource_id,
                            "mediaType": RESOURCE_MEDIA_TYPE,
                        },
                        {
                            "rel": "human-view",
                            "href": f"{base_url}/directory",
                            "mediaType": "text/html",
                        },
                    ]
                    + [
                        {
                            "rel": "source",
                            "href": site["agentDescription"],
                            "mediaType": "application/ld+json",
                            "title": site["name"],
                        }
                        for site in sites
                    ],
                    "affordances": affordances,
                    "provenance": {
                        "publisher": identity.did,
                        "createdAt": created_at,
                        "updatedAt": _now(),
                        "canonical": resource_id,
                    },
                    "data": {
                        "counts": store.counts(),
                        "sites": sites,
                        "admission": (
                            "live DID-WBA and eddsa-jcs-2022 proof verification"
                        ),
                    },
                },
            )

        def search_resource(self, query: str, limit: int = 20) -> dict[str, Any]:
            results = store.search(query, limit=limit)
            parameters = urlencode({"q": query, "limit": limit})
            resource_id = (
                f"{base_url}/registry/resources/search.json?{parameters}"
            )
            links = [
                {
                    "rel": "self",
                    "href": resource_id,
                    "mediaType": RESOURCE_MEDIA_TYPE,
                },
                {
                    "rel": "collection",
                    "href": f"{base_url}/registry/resources/index.json",
                    "mediaType": RESOURCE_MEDIA_TYPE,
                },
            ]
            links.extend(
                {
                    "rel": "item",
                    "href": result["source"]["resource"],
                    "mediaType": RESOURCE_MEDIA_TYPE,
                    "title": result["name"],
                }
                for result in results
            )
            return _sign(
                identity,
                {
                    "@context": f"{base_url}/agent-web/0.2/context.jsonld",
                    "@id": resource_id,
                    "@type": ["AgentWebCollection", "SearchResults"],
                    "agentWeb": {"version": AGENT_WEB_VERSION, "kind": "collection"},
                    "name": f"Registry search: {query}",
                    "description": (
                        "Registry-signed pointers retaining source publisher "
                        "proofs and verification evidence."
                    ),
                    "links": links,
                    "affordances": empty_affordances(),
                    "provenance": {
                        "publisher": identity.did,
                        "createdAt": _now(),
                        "updatedAt": _now(),
                        "canonical": resource_id,
                        "sources": [
                            result["source"]["resource"] for result in results
                        ],
                    },
                    "data": {
                        "query": query,
                        "count": len(results),
                        "results": results,
                    },
                    "extensions": {
                        "registryVerification": {
                            "sourceProofsPreserved": True,
                            "digestCanonicalization": "RFC8785-JCS",
                            "registryDoesNotReplaceSourceTrust": True,
                        }
                    },
                },
            )

    return RegistryAgent()


def create_app(
    *,
    database: str | Path = ":memory:",
    nonce_database: str | Path = ":memory:",
    handle_database: str | Path | None = None,
    base_url: str = "https://localhost:8643",
    identity: PublisherIdentity | None = None,
    allowed_origins: tuple[str, ...] = (),
    metrics_token: str | None = None,
    operator_token: str | None = None,
) -> FastAPI:
    base_url = base_url.rstrip("/")
    identity = identity or generate_publisher_identity(
        base_url=base_url,
        agent_name="registry",
        agent_description_path="/registry/ad.json",
    )
    store = RegistryStore(database)
    agent = _build_agent(identity=identity, store=store, base_url=base_url)
    app = FastAPI(
        title="Agent Web Registry",
        version="0.2.0",
        docs_url=None,
        redoc_url=None,
    )
    app.include_router(agent.router())
    mount_agent_web_profile(app, base_url)
    mount_identity(
        app,
        identity,
        agent_description_url=f"{base_url}/registry/ad.json",
    )
    handle_store = (
        mount_identity_handle(app, identity, handle_database)
        if handle_database is not None and identity.handle is not None
        else None
    )

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "publisher": identity.did,
            "entryPoint": "/registry/resources/index.json",
            **store.counts(),
        }

    @app.get("/registry/resources/index.json")
    async def collection() -> JSONResponse:
        return resource_response(agent.collection_resource())

    @app.get("/registry/resources/search.json")
    async def search_resource(
        q: str = Query(min_length=1, max_length=200),
        limit: int = Query(default=20, ge=1, le=100),
    ) -> JSONResponse:
        return resource_response(agent.search_resource(q, limit))

    @app.get("/directory", response_class=HTMLResponse)
    async def directory(q: str = "") -> HTMLResponse:
        results = store.search(q, limit=50) if q.strip() else []
        return HTMLResponse(_render_directory(store, q, results))

    nonce_store = install_security(
        app,
        SecurityConfig(
            identity=identity,
            base_url=base_url,
            nonce_database=nonce_database,
            allowed_origins=allowed_origins,
        ),
    )
    install_maintenance(app, operator_token=operator_token, base_url=base_url)
    readiness = {
        "registryDatabase": store.integrity_check,
        "nonceDatabase": nonce_store.integrity_check,
    }
    if handle_store is not None:
        readiness["handleDatabase"] = handle_store.integrity_check
    install_observability(
        app,
        service_name="registry",
        readiness_checks=readiness,
        metrics_token=metrics_token,
    )
    app.state.registry_store = store
    app.state.registry_agent = agent
    app.state.publisher_identity = identity
    app.state.nonce_store = nonce_store
    app.state.handle_store = handle_store

    def close() -> None:
        nonce_store.close()
        store.close()
        if handle_store is not None:
            handle_store.close()
        identity_close = getattr(identity, "close", None)
        if callable(identity_close):
            identity_close()

    app.state.close = close
    return app


def _sign(
    identity: PublisherIdentity,
    document: dict[str, Any],
) -> dict[str, Any]:
    return identity.sign_resource(document)


def _render_directory(
    store: RegistryStore,
    query: str,
    results: list[dict[str, Any]],
) -> str:
    sites = "".join(
        f"<li><strong>{escape(site['name'])}</strong> "
        f"<code>{escape(site['publisher'])}</code> "
        f"({site['resourceCount']} resources)</li>"
        for site in store.sites()
    ) or "<li>No publishers indexed.</li>"
    cards = "".join(
        f"""<article><h2>{escape(result['name'])}</h2>
<p>{escape(result['description'])}</p>
<a href="{escape(result['source']['resource'])}">canonical source</a>
<code>{escape(result['source']['publisher'])}</code></article>"""
        for result in results
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent Web Registry</title><style>
body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}}
input{{width:70%;padding:.7rem}}button{{padding:.7rem}}article{{border:1px solid #bbb;
padding:1rem;margin:1rem 0}}code{{display:block;overflow-wrap:anywhere;color:#555}}
</style></head><body><h1>Agent Web Registry</h1>
<p>Only live proof-verified Agent Web resources enter this local index.</p>
<form><input name="q" value="{escape(query)}" maxlength="200">
<button>Search</button></form><h2>Publishers</h2><ul>{sites}</ul>{cards}
</body></html>"""
