"""Secure-by-default HTTP and DID-WBA authentication boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch
from pathlib import Path
import sqlite3
from threading import Lock
from typing import Awaitable, Callable
from urllib.parse import urlsplit

from anp.authentication.did_wba_verifier import (
    DidWbaVerifier,
    DidWbaVerifierConfig,
    DidWbaVerifierError,
)
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from .identity import ManagedPublisherIdentity, PublisherIdentity


DEFAULT_PUBLIC_GET_PATHS = (
    "/health",
    "/live",
    "/ready",
    "/metrics",
    "/.well-known/agent-descriptions",
    "/.well-known/handle/*",
    "/agent-web/0.2",
    "/agent-web/0.2/*",
    "*/did.json",
    "*/ad.json",
    "*/interface.json",
    "*/resources/*.json",
    "*/resources/*/*.json",
    "/forum",
    "/forum/*",
    "/weather",
    "/weather/*",
    "/directory",
    "/directory/*",
)


class NonceStore:
    """Atomic, persistent replay cache shared by server workers."""

    def __init__(
        self,
        database: str | Path,
        *,
        expiration_minutes: int = 6,
    ) -> None:
        self._connection = sqlite3.connect(
            str(database),
            check_same_thread=False,
            isolation_level=None,
        )
        self._connection.execute("PRAGMA journal_mode=WAL")
        schema_version = int(
            self._connection.execute("PRAGMA user_version").fetchone()[0]
        )
        if schema_version > 1:
            self._connection.close()
            raise RuntimeError("nonce database is newer than this runtime")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_nonces (
                did TEXT NOT NULL,
                nonce TEXT NOT NULL,
                claimed_at TEXT NOT NULL,
                PRIMARY KEY (did, nonce)
            )
            """
        )
        self._connection.execute("PRAGMA user_version = 1")
        self._lock = Lock()
        self._expiration = timedelta(minutes=expiration_minutes)

    def claim(self, did: str, nonce: str) -> bool:
        """Claim a nonce exactly once, returning false on replay."""

        now = datetime.now(timezone.utc)
        cutoff = (now - self._expiration).isoformat()
        with self._lock:
            self._connection.execute(
                "DELETE FROM auth_nonces WHERE claimed_at < ?",
                (cutoff,),
            )
            try:
                self._connection.execute(
                    "INSERT INTO auth_nonces(did, nonce, claimed_at) VALUES (?, ?, ?)",
                    (did, nonce, now.isoformat()),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def integrity_check(self) -> bool:
        with self._lock:
            result = self._connection.execute("PRAGMA quick_check").fetchall()
            return len(result) == 1 and result[0][0] == "ok"


@dataclass(frozen=True, slots=True)
class SecurityConfig:
    """HTTP security policy for one independently deployed publisher."""

    identity: PublisherIdentity | ManagedPublisherIdentity
    base_url: str
    nonce_database: str | Path = ":memory:"
    max_request_bytes: int = 256 * 1024
    public_get_paths: tuple[str, ...] = DEFAULT_PUBLIC_GET_PATHS
    allowed_origins: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("Agent Web publishers require an HTTPS base URL")
        if self.max_request_bytes < 1024:
            raise ValueError("max_request_bytes is unreasonably small")


def install_security(app: FastAPI, config: SecurityConfig) -> NonceStore:
    """Install transport, request, replay, and DID-WBA controls."""

    parsed = urlsplit(config.base_url)
    expected_authority = parsed.netloc.lower()
    nonce_store = NonceStore(config.nonce_database)
    verifier = DidWbaVerifier(
        DidWbaVerifierConfig(
            jwt_private_key=config.identity.private_key_pem,
            jwt_public_key=config.identity.public_key_pem,
            jwt_algorithm="EdDSA",
            access_token_expire_minutes=15,
            nonce_expiration_minutes=6,
            timestamp_expiration_minutes=5,
            external_nonce_validator=nonce_store.claim,
            allowed_domains=[parsed.hostname],
            allow_http_signatures=True,
            allow_legacy_didwba=False,
            emit_authentication_info_header=True,
            emit_legacy_authorization_header=False,
            require_nonce_for_http_signatures=True,
        )
    )

    @app.middleware("http")
    async def secure_boundary(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response: Response
        try:
            if request.url.scheme != "https":
                return _problem(400, "HTTPS is required")
            if request.headers.get("host", "").lower() != expected_authority:
                return _problem(421, "request authority is not configured")

            content_length = request.headers.get("content-length")
            if content_length is not None:
                try:
                    parsed_length = int(content_length)
                    if parsed_length < 0:
                        return _problem(400, "invalid Content-Length")
                    if parsed_length > config.max_request_bytes:
                        return _problem(413, "request body is too large")
                except ValueError:
                    return _problem(400, "invalid Content-Length")

            public = (
                request.method in {"GET", "HEAD"}
                and any(
                    fnmatch(request.url.path, pattern)
                    for pattern in config.public_get_paths
                )
            )
            auth_result = None
            if not public:
                if request.method == "POST" and not request.headers.get(
                    "content-type", ""
                ).lower().startswith("application/json"):
                    return _problem(415, "RPC requests must use application/json")
                chunks = bytearray()
                async for chunk in request.stream():
                    chunks.extend(chunk)
                    if len(chunks) > config.max_request_bytes:
                        return _problem(413, "request body is too large")
                body = bytes(chunks)
                request._body = body
                auth_result = await verifier.verify_request(
                    method=request.method,
                    url=str(request.url),
                    headers=dict(request.headers),
                    body=body,
                    domain=parsed.hostname,
                )
            request.state.auth_result = auth_result
            request.state.did = auth_result.get("did") if auth_result else None
            response = await call_next(request)
            if auth_result:
                for name, value in auth_result.get("response_headers", {}).items():
                    response.headers[name] = value
        except DidWbaVerifierError as exc:
            response = JSONResponse(
                status_code=exc.status_code,
                content={"detail": str(exc)},
                headers=exc.headers,
            )
        except Exception:
            response = _problem(500, "internal server error")

        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        if request.url.path.endswith("/rpc"):
            response.headers["Cache-Control"] = "no-store"
        origin = request.headers.get("origin")
        if origin and origin in config.allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
        return response

    return nonce_store


def _problem(status: int, detail: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"detail": detail})
