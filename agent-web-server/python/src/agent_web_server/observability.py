"""Low-cardinality metrics, structured access logs, liveness, and readiness."""

from __future__ import annotations

import hmac
import inspect
import json
import logging
from time import perf_counter
from typing import Awaitable, Callable, Mapping
from uuid import uuid4

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from prometheus_client.exposition import CONTENT_TYPE_LATEST


ReadinessCheck = Callable[[], bool | Awaitable[bool]]
LOGGER = logging.getLogger("agent_web.access")


class ServiceObservability:
    """Metrics owned by one ASGI application, isolated for testability."""

    def __init__(self, service: str) -> None:
        self.service = service
        self.registry = CollectorRegistry(auto_describe=True)
        self.requests = Counter(
            "agent_web_http_requests_total",
            "Completed Agent Web HTTP requests.",
            ("service", "method", "route", "status_class"),
            registry=self.registry,
        )
        self.duration = Histogram(
            "agent_web_http_request_duration_seconds",
            "Agent Web HTTP request duration.",
            ("service", "method", "route"),
            registry=self.registry,
        )
        self.in_flight = Gauge(
            "agent_web_http_requests_in_flight",
            "Agent Web HTTP requests currently executing.",
            ("service",),
            registry=self.registry,
        )
        self.security_events = Counter(
            "agent_web_security_events_total",
            "Security-relevant HTTP responses.",
            ("service", "event"),
            registry=self.registry,
        )
        self.ready = Gauge(
            "agent_web_ready",
            "Whether all local readiness checks pass.",
            ("service",),
            registry=self.registry,
        )
        self.maintenance = Gauge(
            "agent_web_maintenance_mode",
            "Whether the publisher is quiesced for maintenance.",
            ("service",),
            registry=self.registry,
        )


def install_observability(
    app: FastAPI,
    *,
    service_name: str,
    readiness_checks: Mapping[str, ReadinessCheck],
    metrics_token: str | None,
) -> ServiceObservability:
    """Install private metrics and public local-state health endpoints."""

    if metrics_token is not None and len(metrics_token.encode("utf-8")) < 32:
        raise ValueError("metrics token must contain at least 32 bytes")
    checks = dict(readiness_checks)
    if not checks:
        raise ValueError("at least one readiness check is required")
    metrics = ServiceObservability(service_name)
    metrics.ready.labels(service_name).set(0)
    metrics.maintenance.labels(service_name).set(0)

    @app.get("/live", include_in_schema=False)
    async def live() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/ready", include_in_schema=False)
    async def ready() -> JSONResponse:
        components: dict[str, bool] = {}
        for name, check in checks.items():
            try:
                result = check()
                if inspect.isawaitable(result):
                    result = await result
                components[name] = result is True
            except Exception:
                components[name] = False
        is_ready = all(components.values())
        metrics.ready.labels(service_name).set(1 if is_ready else 0)
        return JSONResponse(
            status_code=200 if is_ready else 503,
            content={
                "status": "ready" if is_ready else "not-ready",
                "components": components,
            },
        )

    @app.get("/metrics", include_in_schema=False)
    async def prometheus_metrics(request: Request) -> Response:
        if metrics_token is None:
            return JSONResponse(status_code=404, content={"detail": "not found"})
        if not _authorized(request, metrics_token):
            return JSONResponse(
                status_code=401,
                content={"detail": "metrics authentication required"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        gate = getattr(app.state, "maintenance_gate", None)
        if gate is not None:
            status = await gate.status()
            metrics.maintenance.labels(service_name).set(
                1 if status.maintenance else 0
            )
        return Response(
            content=generate_latest(metrics.registry),
            media_type=CONTENT_TYPE_LATEST,
        )

    @app.middleware("http")
    async def observe(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        request_id = uuid4().hex
        started = perf_counter()
        metrics.in_flight.labels(service_name).inc()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
        except Exception:
            LOGGER.exception(
                json.dumps(
                    {
                        "event": "http_request_failed",
                        "service": service_name,
                        "requestId": request_id,
                    },
                    separators=(",", ":"),
                )
            )
            response = JSONResponse(
                status_code=500,
                content={"detail": "internal server error"},
            )
        finally:
            elapsed = perf_counter() - started
            metrics.in_flight.labels(service_name).dec()
        route = _route_label(request)
        status_class = f"{status // 100}xx"
        metrics.requests.labels(
            service_name, request.method, route, status_class
        ).inc()
        metrics.duration.labels(service_name, request.method, route).observe(elapsed)
        event = {
            401: "authentication_denied",
            403: "authorization_denied",
            421: "authority_rejected",
            429: "rate_limited",
        }.get(status)
        if event is not None:
            metrics.security_events.labels(service_name, event).inc()
        response.headers["X-Request-ID"] = request_id
        LOGGER.info(
            json.dumps(
                {
                    "event": "http_request",
                    "service": service_name,
                    "requestId": request_id,
                    "method": request.method,
                    "route": route,
                    "status": status,
                    "durationMs": round(elapsed * 1000, 3),
                    "authenticated": bool(getattr(request.state, "did", None)),
                },
                separators=(",", ":"),
            )
        )
        return response

    app.state.observability = metrics
    return metrics


def _route_label(request: Request) -> str:
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    if isinstance(path, str):
        return path
    if request.url.path.startswith("/ops/maintenance"):
        return "/ops/maintenance/{action}"
    return "unmatched"


def _authorized(request: Request, expected: str) -> bool:
    value = request.headers.get("authorization", "")
    scheme, separator, token = value.partition(" ")
    return bool(
        separator
        and scheme.casefold() == "bearer"
        and hmac.compare_digest(token.encode("utf-8"), expected.encode("utf-8"))
    )
