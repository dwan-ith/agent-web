"""Forecast: a signed Agent Web bridge to the real Open-Meteo API."""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import quote

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
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from libagentweb import (
    AGENT_WEB_VERSION,
    RESOURCE_MEDIA_TYPE,
    anp_action,
    empty_affordances,
    sign_resource,
)

from .provider import ForecastProvider, OpenMeteoProvider


def _build_agent(
    *,
    identity: PublisherIdentity,
    provider: ForecastProvider,
    base_url: str,
    moltbook_entrypoint: str | None,
) -> Any:
    published_at = _now()

    @anp_agent(
        AgentConfig(
            name="Forecast",
            did=identity.did,
            prefix="/forecast",
            description="Current weather from Open-Meteo as signed Agent Web resources.",
            tags=["ANP", "Agent Web", "Forecast", "Open-Meteo"],
        )
    )
    class ForecastAgent:
        def customize_ad(
            self,
            document: dict[str, Any],
            request_base_url: str,
        ) -> dict[str, Any]:
            document["agentWeb"] = {
                "profile": f"{base_url}/agent-web/0.2",
                "version": AGENT_WEB_VERSION,
                "entryPoint": f"{base_url}/forecast/resources/index.json",
                "resourceMediaType": RESOURCE_MEDIA_TYPE,
                "humanView": f"{base_url}/weather",
            }
            document["security"] = {
                "authentication": "didwba-http-message-signatures",
                "transport": "TLS",
                "objectProof": "eddsa-jcs-2022",
            }
            document.setdefault("Infomations", []).append(
                {
                    "type": "AgentWebCollection",
                    "description": "Forecast Agent Web entry resource",
                    "url": f"{base_url}/forecast/resources/index.json",
                }
            )
            return identity.sign_document(document)

        @interface(description="List configured live forecast locations.")
        async def list_forecasts(self, ctx: Context) -> dict[str, Any]:
            return self.collection_resource()

        @interface(description="Fetch a current Open-Meteo forecast by slug.")
        async def get_forecast(
            self,
            location: str,
            ctx: Context,
        ) -> dict[str, Any]:
            return await self.forecast_resource(location)

        def collection_resource(self) -> dict[str, Any]:
            resource_id = f"{base_url}/forecast/resources/index.json"
            links = [
                {
                    "rel": "item",
                    "href": f"{base_url}/forecast/resources/{location.slug}.json",
                    "mediaType": RESOURCE_MEDIA_TYPE,
                    "title": location.name,
                }
                for location in provider.locations
            ]
            links.extend(
                [
                    {
                        "rel": "self",
                        "href": resource_id,
                        "mediaType": RESOURCE_MEDIA_TYPE,
                    },
                    {
                        "rel": "human-view",
                        "href": f"{base_url}/weather",
                        "mediaType": "text/html",
                    },
                    {
                        "rel": "describedby",
                        "href": f"{base_url}/forecast/ad.json",
                        "mediaType": "application/ld+json",
                    },
                ]
            )
            if moltbook_entrypoint:
                links.append(
                    {
                        "rel": "related",
                        "href": moltbook_entrypoint,
                        "mediaType": RESOURCE_MEDIA_TYPE,
                        "title": "Moltbook discussions",
                    }
                )
            affordances = empty_affordances()
            affordances["actions"]["getForecast"] = anp_action(
                description="Fetch current weather by configured location slug.",
                rpc_url=f"{base_url}/forecast/rpc",
                method="get_forecast",
                input_schema={
                    "type": "object",
                    "required": ["location"],
                    "additionalProperties": False,
                    "properties": {
                        "location": {
                            "type": "string",
                            "enum": sorted(item.slug for item in provider.locations),
                        }
                    },
                },
                output_schema={"$ref": "urn:agent-web:schema:resource:0.2"},
                safe=True,
                idempotent=True,
                authorization_level="normal",
            )
            return _sign_resource(
                identity,
                {
                    "@context": f"{base_url}/agent-web/0.2/context.jsonld",
                    "@id": resource_id,
                    "@type": ["AgentWebCollection", "WeatherForecastService"],
                    "agentWeb": {"version": AGENT_WEB_VERSION, "kind": "collection"},
                    "name": "Live forecast locations",
                    "description": "Configured locations backed by Open-Meteo.",
                    "links": links,
                    "affordances": affordances,
                    "provenance": {
                        "publisher": identity.did,
                        "createdAt": published_at,
                        "updatedAt": published_at,
                        "canonical": resource_id,
                        "sources": ["https://open-meteo.com/en/docs"],
                    },
                    "data": {
                        "count": len(provider.locations),
                        "locations": [
                            {"slug": item.slug, "name": item.name}
                            for item in provider.locations
                        ],
                    },
                },
            )

        async def forecast_resource(self, location: str) -> dict[str, Any]:
            record = await provider.get(location)
            slug = str(record["slug"])
            resource_id = f"{base_url}/forecast/resources/{slug}.json"
            retrieved = str(record["retrievedAt"])
            valid_through = str(record["validThrough"])
            return _sign_resource(
                identity,
                {
                    "@context": f"{base_url}/agent-web/0.2/context.jsonld",
                    "@id": resource_id,
                    "@type": ["AgentWebResource", "WeatherForecast"],
                    "agentWeb": {"version": AGENT_WEB_VERSION, "kind": "resource"},
                    "name": f"Forecast for {record['location']}",
                    "description": (
                        f"{record['condition']}, {record['temperatureC']} °C."
                    ),
                    "links": [
                        {
                            "rel": "self",
                            "href": resource_id,
                            "mediaType": RESOURCE_MEDIA_TYPE,
                        },
                        {
                            "rel": "collection",
                            "href": f"{base_url}/forecast/resources/index.json",
                            "mediaType": RESOURCE_MEDIA_TYPE,
                        },
                        {
                            "rel": "human-view",
                            "href": f"{base_url}/weather/{slug}",
                            "mediaType": "text/html",
                        },
                    ],
                    "affordances": empty_affordances(),
                    "provenance": {
                        "publisher": identity.did,
                        "createdAt": retrieved,
                        "updatedAt": retrieved,
                        "expiresAt": valid_through,
                        "canonical": resource_id,
                        "sources": [str(record["source"])],
                    },
                    "data": record,
                },
            )

    return ForecastAgent()


def create_app(
    *,
    base_url: str = "https://localhost:8100",
    identity: PublisherIdentity | None = None,
    provider: ForecastProvider | None = None,
    nonce_database: str | Path = ":memory:",
    handle_database: str | Path | None = None,
    moltbook_entrypoint: str | None = None,
    allowed_origins: tuple[str, ...] = (),
    metrics_token: str | None = None,
    operator_token: str | None = None,
) -> FastAPI:
    base_url = base_url.rstrip("/")
    identity = identity or generate_publisher_identity(
        base_url=base_url,
        agent_name="forecast",
        agent_description_path="/forecast/ad.json",
    )
    provider = provider or OpenMeteoProvider()
    agent = _build_agent(
        identity=identity,
        provider=provider,
        base_url=base_url,
        moltbook_entrypoint=moltbook_entrypoint,
    )
    app = FastAPI(
        title="Forecast Agent Web publisher",
        version="0.2.0",
        description="A signed ANP bridge to Open-Meteo.",
        docs_url=None,
        redoc_url=None,
    )
    app.include_router(agent.router())
    mount_agent_web_profile(app, base_url)
    mount_identity(
        app,
        identity,
        agent_description_url=f"{base_url}/forecast/ad.json",
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
            "agentWebVersion": AGENT_WEB_VERSION,
            "publisher": identity.did,
            "upstream": "Open-Meteo",
            "entryPoint": "/forecast/resources/index.json",
        }

    @app.get("/forecast/resources/index.json")
    async def collection() -> JSONResponse:
        return resource_response(agent.collection_resource())

    @app.get("/forecast/resources/{location}.json")
    async def forecast(location: str) -> JSONResponse:
        try:
            return resource_response(await agent.forecast_resource(location))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail="forecast upstream is unavailable",
            ) from exc

    @app.get("/weather", response_class=HTMLResponse)
    async def weather() -> HTMLResponse:
        return HTMLResponse(_render_weather(provider))

    @app.get("/weather/{location}", response_class=HTMLResponse)
    async def weather_location(location: str) -> HTMLResponse:
        try:
            resource = await agent.forecast_resource(location)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail="forecast upstream is unavailable",
            ) from exc
        return HTMLResponse(
            _render_weather(provider, selected=resource["data"]),
            headers={
                "Link": (
                    f'<{resource["@id"]}>; rel="canonical"; '
                    f'type="{RESOURCE_MEDIA_TYPE}"'
                )
            },
        )

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
    readiness = {"nonceDatabase": nonce_store.integrity_check}
    if handle_store is not None:
        readiness["handleDatabase"] = handle_store.integrity_check
    install_observability(
        app,
        service_name="forecast",
        readiness_checks=readiness,
        metrics_token=metrics_token,
    )
    app.state.forecast_agent = agent
    app.state.publisher_identity = identity
    app.state.nonce_store = nonce_store
    app.state.handle_store = handle_store

    def close() -> None:
        nonce_store.close()
        if handle_store is not None:
            handle_store.close()
        identity_close = getattr(identity, "close", None)
        if callable(identity_close):
            identity_close()

    app.state.close = close
    return app


def _sign_resource(
    identity: PublisherIdentity,
    document: dict[str, Any],
) -> dict[str, Any]:
    return identity.sign_resource(document)


def _render_weather(
    provider: ForecastProvider,
    selected: dict[str, Any] | None = None,
) -> str:
    cards = "".join(
        f"""<a class="card" href="/weather/{quote(item.slug)}">
<span>Live Open-Meteo data</span><strong>{escape(item.name)}</strong></a>"""
        for item in provider.locations
    )
    detail = ""
    if selected:
        detail = f"""<section><small>AGENT WEB RESOURCE</small>
<h1>{escape(str(selected['location']))}</h1>
<div class="temperature">{float(selected['temperatureC']):.1f} °C</div>
<p>{escape(str(selected['condition']))}</p>
<p>Observed {escape(str(selected['observedAt']))}; source: Open-Meteo.</p></section>"""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Forecast — Agent Web bridge</title><style>
:root{{font-family:system-ui,sans-serif;color:#172033;background:#eef4f7}}body{{margin:0}}
header{{padding:2rem 6vw;background:#13233f;color:white}}main{{width:min(900px,88vw);margin:2rem auto}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem}}
.card{{display:grid;gap:.5rem;padding:1.25rem;background:white;color:inherit;text-decoration:none;
border:1px solid #d5e0e7;border-radius:14px}}small,.card span{{color:#4b6b78}}
section{{padding:1.5rem;border-left:4px solid #e97d45;background:white;margin-bottom:2rem}}
.temperature{{font-size:4rem;font-weight:700}}</style></head><body>
<header><small>HUMAN VIEW OF AGENT WEB</small><h1>Forecast</h1>
<p>Signed structured weather from the Open-Meteo API.</p></header>
<main>{detail}<div class="grid">{cards}</div></main></body></html>"""


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
