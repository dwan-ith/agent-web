"""Operator-authenticated write draining for consistent service snapshots."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hmac
from typing import Awaitable, Callable
from urllib.parse import urlsplit

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse


SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MAINTENANCE_PREFIX = "/ops/maintenance"


@dataclass(frozen=True, slots=True)
class MaintenanceStatus:
    draining: bool
    maintenance: bool
    active_mutations: int

    def document(self) -> dict[str, bool | int | str]:
        return {
            "status": "maintenance" if self.maintenance else (
                "draining" if self.draining else "available"
            ),
            "draining": self.draining,
            "maintenance": self.maintenance,
            "activeMutations": self.active_mutations,
        }


class MaintenanceGate:
    """Drain in-flight mutations and reject new mutations while quiesced."""

    def __init__(self) -> None:
        self._condition = asyncio.Condition()
        self._control_lock = asyncio.Lock()
        self._draining = False
        self._maintenance = False
        self._active_mutations = 0

    async def begin_mutation(self) -> bool:
        async with self._condition:
            if self._draining or self._maintenance:
                return False
            self._active_mutations += 1
            return True

    async def end_mutation(self) -> None:
        async with self._condition:
            if self._active_mutations < 1:
                raise RuntimeError("maintenance mutation counter underflow")
            self._active_mutations -= 1
            if self._active_mutations == 0:
                self._condition.notify_all()

    async def enter(self, *, timeout: float = 30.0) -> MaintenanceStatus:
        if timeout <= 0 or timeout > 300:
            raise ValueError("maintenance drain timeout must be in (0, 300]")
        async with self._control_lock:
            async with self._condition:
                if self._maintenance:
                    return self._status_unlocked()
                self._draining = True
                try:
                    await asyncio.wait_for(
                        self._condition.wait_for(
                            lambda: self._active_mutations == 0
                        ),
                        timeout=timeout,
                    )
                except TimeoutError:
                    self._draining = False
                    self._condition.notify_all()
                    raise
                self._maintenance = True
                self._draining = False
                return self._status_unlocked()

    async def exit(self) -> MaintenanceStatus:
        async with self._control_lock:
            async with self._condition:
                self._draining = False
                self._maintenance = False
                self._condition.notify_all()
                return self._status_unlocked()

    async def status(self) -> MaintenanceStatus:
        async with self._condition:
            return self._status_unlocked()

    def _status_unlocked(self) -> MaintenanceStatus:
        return MaintenanceStatus(
            draining=self._draining,
            maintenance=self._maintenance,
            active_mutations=self._active_mutations,
        )


def install_maintenance(
    app: FastAPI,
    *,
    operator_token: str | None,
    base_url: str,
    drain_timeout: float = 30.0,
) -> MaintenanceGate:
    """Install an outer write gate and private maintenance control surface."""

    if operator_token is not None and len(operator_token.encode("utf-8")) < 32:
        raise ValueError("operator token must contain at least 32 bytes")
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("maintenance boundary requires an HTTPS base URL")
    expected_authority = parsed.netloc.casefold()
    gate = MaintenanceGate()

    @app.middleware("http")
    async def maintenance_boundary(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if request.url.path.startswith(MAINTENANCE_PREFIX):
            if request.url.scheme != "https":
                return _response(400, {"detail": "HTTPS is required"})
            if request.headers.get("host", "").casefold() != expected_authority:
                return _response(
                    421, {"detail": "request authority is not configured"}
                )
            if operator_token is None:
                return _response(404, {"detail": "not found"})
            if not _authorized(request, operator_token):
                return _response(
                    401,
                    {"detail": "operator authentication required"},
                    headers={"WWW-Authenticate": "Bearer"},
                )
            if request.method == "GET" and request.url.path == (
                f"{MAINTENANCE_PREFIX}/status"
            ):
                return _response(200, (await gate.status()).document())
            if request.method == "POST" and request.url.path == (
                f"{MAINTENANCE_PREFIX}/enter"
            ):
                try:
                    status = await gate.enter(timeout=drain_timeout)
                except TimeoutError:
                    return _response(
                        503,
                        {"detail": "mutation drain timed out"},
                        headers={"Retry-After": "5"},
                    )
                return _response(200, status.document())
            if request.method == "POST" and request.url.path == (
                f"{MAINTENANCE_PREFIX}/exit"
            ):
                return _response(200, (await gate.exit()).document())
            return _response(404, {"detail": "not found"})

        if request.method in SAFE_METHODS:
            return await call_next(request)
        if not await gate.begin_mutation():
            return JSONResponse(
                status_code=503,
                content={"detail": "publisher is in maintenance mode"},
                headers={"Retry-After": "5"},
            )
        try:
            return await call_next(request)
        finally:
            await gate.end_mutation()

    app.state.maintenance_gate = gate
    return gate


def _authorized(request: Request, expected: str) -> bool:
    value = request.headers.get("authorization", "")
    scheme, separator, token = value.partition(" ")
    return bool(
        separator
        and scheme.casefold() == "bearer"
        and hmac.compare_digest(token.encode("utf-8"), expected.encode("utf-8"))
    )


def _response(
    status: int,
    content: dict[str, bool | int | str],
    *,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    response = JSONResponse(status_code=status, content=content, headers=headers)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    return response
