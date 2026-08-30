"""Loopback daemon: Web navigation, identity custody, and optional ANP calls."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from html import escape
from pathlib import Path
import hmac
import secrets
from typing import Any, TYPE_CHECKING
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from libagentweb import (
    Ed25519Signer,
    ResourceTrustError,
    WebActionConfirmationRequired,
    WebAgentBrowser,
    build_caller_controller,
)
from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from agent_web_server import PublisherIdentity


SESSION_TOKEN_HEADER = "X-Agent-Web-Browser-Token"


class ConnectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agentDescriptionUrl: str = Field(min_length=1, max_length=2048)


class OpenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    resourceUrl: str = Field(min_length=1, max_length=2048)


class OriginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    origin: str = Field(min_length=1, max_length=512)


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
    params: dict[str, Any] = Field(default_factory=dict)
    confirmed: bool = False
    resourceUrl: str | None = Field(default=None, max_length=2048)


class BrowserDaemon:
    """Single-user browser session; safe because the server binds loopback."""

    def __init__(
        self,
        *,
        identity: PublisherIdentity | None = None,
        did_document_path: str | Path | None = None,
        private_key_path: str | Path | None = None,
        allow_private_networks: bool = False,
        anp_browser_factory: Any | None = None,
        caller_controller: str | None = None,
        caller_signer: Ed25519Signer | None = None,
    ) -> None:
        self.identity = identity
        self.did_document_path = (
            str(did_document_path) if did_document_path is not None else None
        )
        self.private_key_path = (
            str(private_key_path) if private_key_path is not None else None
        )
        self.allow_private_networks = allow_private_networks
        self.anp_browser_factory = anp_browser_factory
        self.caller_controller = caller_controller
        self.caller_signer = caller_signer
        self.browser: Any | None = None
        self.browser_binding: str | None = None
        self.connected_agent: dict[str, str] | None = None
        self._lock = asyncio.Lock()

    def status(self) -> dict[str, Any]:
        return {
            "ready": True,
            "callerDid": getattr(self.identity, "did", None),
            "callerController": self.caller_controller,
            "connectedAgent": deepcopy(self.connected_agent),
            "allowedOrigins": (
                sorted(self.browser.allowed_origins) if self.browser else []
            ),
        }

    async def connect(self, agent_description_url: str) -> dict[str, Any]:
        async with self._lock:
            if "://" in agent_description_url and not agent_description_url.startswith(
                "https://"
            ):
                raise ValueError("discovery URLs must use HTTPS")
            if agent_description_url.startswith("https://"):
                _https_url(agent_description_url)
                if urlsplit(agent_description_url).path == "/.well-known/agent-web":
                    web_candidate = WebAgentBrowser(
                        agent_description_url,
                        allow_private_networks=self.allow_private_networks,
                        caller_controller=self.caller_controller,
                        caller_signer=self.caller_signer,
                    )
                    entry = await web_candidate.open_entrypoint()
                    self.browser = web_candidate
                    self.browser_binding = "Agent Web HTTP"
                    self.connected_agent = {
                        "name": str(entry.get("name", urlsplit(agent_description_url).hostname)),
                        "description": str(
                            entry.get("description", "Web-native Agent Web publisher")
                        ),
                        "url": agent_description_url,
                        "binding": "Agent Web HTTP",
                    }
                    return {
                        "status": self.status(),
                        "entry": {"resource": entry, "verified": True},
                    }
                browser_factory = self._anp_browser()
                candidate = browser_factory(
                    agent_description_url,
                    did_document_path=self.did_document_path,
                    private_key_path=self.private_key_path,
                    allow_private_networks=self.allow_private_networks,
                )
            else:
                browser_factory = self._anp_browser()
                candidate = await browser_factory.from_handle_async(
                    agent_description_url,
                    did_document_path=self.did_document_path,
                    private_key_path=self.private_key_path,
                    allow_private_networks=self.allow_private_networks,
                )
            description = await candidate.discover_async()
            entry = await candidate.open_entrypoint_async()
            self.browser = candidate
            self.browser_binding = "ANP compatibility"
            self.connected_agent = {
                "name": str(description["name"]),
                "description": str(description["description"]),
                "url": candidate.agent_description_url,
                "binding": "ANP compatibility",
            }
            if candidate.handle_binding is not None:
                self.connected_agent["handle"] = candidate.handle_binding.handle
                self.connected_agent["bindingGeneration"] = (
                    candidate.handle_binding.binding_generation
                )
            return {
                "status": self.status(),
                "entry": {"resource": entry, "verified": True},
            }

    async def open(self, resource_url: str) -> dict[str, Any]:
        browser = self._require_browser()
        if self.browser_binding == "Agent Web HTTP":
            resource = await browser.open(resource_url)
        else:
            resource = await browser.open_async(resource_url)
        return {"resource": resource, "verified": True}

    def allow_origin(self, origin: str) -> dict[str, Any]:
        browser = self._require_browser()
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ValueError("origin must be an absolute HTTPS origin")
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise ValueError("origin must be an absolute HTTPS origin")
        netloc = f"{hostname}:{parsed.port}" if parsed.port is not None else hostname
        normalized = f"https://{netloc}"
        browser.allowed_origins.add(normalized)
        return self.status()

    async def call(
        self,
        method: str,
        params: dict[str, Any],
        *,
        confirmed: bool,
        resource_url: str | None = None,
    ) -> dict[str, Any]:
        browser = self._require_browser()
        if self.browser_binding == "Agent Web HTTP":
            resource = await browser.invoke(
                method,
                params,
                confirmed=confirmed,
                resource_url=resource_url,
            )
        else:
            resource = await browser.call_async(
                method,
                params,
                confirmed=confirmed,
                resource_url=resource_url,
            )
        return {"resource": resource, "verified": True}

    def _require_browser(self) -> Any:
        if self.browser is None:
            raise ValueError("connect to Web discovery or an optional Agent Description first")
        return self.browser

    def _anp_browser(self) -> Any:
        if self.identity is None or self.did_document_path is None or self.private_key_path is None:
            raise ValueError(
                "ANP compatibility requires a browser identity and private key"
            )
        if self.anp_browser_factory is not None:
            return self.anp_browser_factory
        try:
            from libagentweb import AgentBrowser
        except ModuleNotFoundError as exc:
            raise ValueError(
                "ANP compatibility is unavailable; install the browser anp extra"
            ) from exc
        return AgentBrowser


def create_app(
    *,
    identity: PublisherIdentity | None = None,
    did_document_path: str | Path | None = None,
    private_key_path: str | Path | None = None,
    base_url: str,
    static_directory: str | Path | None = None,
    allow_private_networks: bool = False,
    anp_browser_factory: Any | None = None,
    caller_controller: str | None = None,
    caller_signer: Ed25519Signer | None = None,
    session_token: str | None = None,
) -> FastAPI:
    """Create the local UI/API server; callers must bind it to loopback.

    Every ``/api`` request and the token-carrying UI entry require a session
    token (generated at startup and printed by the CLI). This keeps other
    local user accounts, sandboxed processes, and web pages from driving the
    custodial key or expanding the origin policy.
    """

    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or parsed.hostname not in {"localhost", "127.0.0.1"}:
        raise ValueError("graphical browser must use an HTTPS loopback base URL")
    if identity is not None:
        try:
            from anp.authentication.did_resolver import build_did_resolution_url
        except ModuleNotFoundError as exc:
            raise ValueError(
                "browser identity requires the optional ANP compatibility extra"
            ) from exc
        if urlsplit(build_did_resolution_url(identity.did)).netloc != parsed.netloc:
            raise ValueError("browser DID-WBA identity is not bound to base_url")
    if (caller_controller is None) != (caller_signer is None):
        raise ValueError("caller_controller and caller_signer must be configured together")
    caller_document = None
    if caller_signer is not None and caller_controller is not None:
        if not caller_controller.startswith(f"{base_url.rstrip('/')}/"):
            raise ValueError("browser caller controller must be bound to base_url")
        caller_document = build_caller_controller(
            caller=caller_controller,
            signer=caller_signer,
        )
    daemon = BrowserDaemon(
        identity=identity,
        did_document_path=did_document_path,
        private_key_path=private_key_path,
        allow_private_networks=allow_private_networks,
        anp_browser_factory=anp_browser_factory,
        caller_controller=caller_controller,
        caller_signer=caller_signer,
    )
    app = FastAPI(
        title="Agent Web Browser daemon",
        version="0.2.0",
        docs_url=None,
        redoc_url=None,
    )
    token = session_token or secrets.token_urlsafe(32)
    app.state.daemon_token = token
    if identity is not None:
        from agent_web_server import mount_identity

        mount_identity(
            app,
            identity,
            agent_description_url=f"{base_url.rstrip('/')}/browser/ad.json",
        )

    @app.middleware("http")
    async def local_boundary(request: Request, call_next: Any) -> Any:
        expected = parsed.netloc.lower()
        if request.headers.get("host", "").lower() != expected:
            return JSONResponse(
                status_code=421,
                content={"detail": "unexpected loopback authority"},
            )
        if request.url.scheme != "https":
            return JSONResponse(
                status_code=400,
                content={"detail": "HTTPS is required"},
            )
        origin = request.headers.get("origin")
        if request.method not in {"GET", "HEAD"} and origin:
            if origin.rstrip("/") != base_url.rstrip("/"):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "cross-origin mutation blocked"},
                )
        if request.url.path.startswith("/api/") or request.url.path == "/":
            presented = (
                request.headers.get(SESSION_TOKEN_HEADER)
                or request.query_params.get("token")
                or ""
            )
            if not hmac.compare_digest(str(presented), token):
                return JSONResponse(
                    status_code=401,
                    content={
                        "detail": (
                            "a valid session token is required; start the "
                            "browser with its launcher command"
                        )
                    },
                )
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; connect-src 'self'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    if identity is not None:
        @app.get("/browser/ad.json")
        async def browser_description() -> dict[str, Any]:
            return identity.sign_document(
                {
                    "protocolType": "ANP",
                    "protocolVersion": "1.1",
                    "type": "AgentApplication",
                    "url": f"{base_url.rstrip('/')}/browser/ad.json",
                    "identifier": identity.did,
                    "name": "Agent Web Browser",
                    "description": "Optional identity-holding compatibility adapter.",
                    "interfaces": [],
                }
            )

    if caller_document is not None:
        @app.get("/.well-known/agent-web-caller")
        async def web_caller_controller() -> JSONResponse:
            return JSONResponse(caller_document, media_type="application/json")

    @app.get("/api/status")
    async def status() -> dict[str, Any]:
        return daemon.status()

    @app.post("/api/connect")
    async def connect(body: ConnectRequest) -> dict[str, Any]:
        return await _safe(daemon.connect(body.agentDescriptionUrl))

    @app.post("/api/open")
    async def open_resource(body: OpenRequest) -> dict[str, Any]:
        return await _safe(daemon.open(body.resourceUrl))

    @app.post("/api/origins")
    async def allow_origin(body: OriginRequest) -> dict[str, Any]:
        try:
            return daemon.allow_origin(body.origin)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/actions")
    async def action(body: ActionRequest) -> dict[str, Any]:
        return await _safe(
            daemon.call(
                body.method,
                body.params,
                confirmed=body.confirmed,
                resource_url=body.resourceUrl,
            )
        )

    assets = Path(static_directory) if static_directory else _default_static_dir()
    index_path = assets / "index.html"
    if index_path.is_file():
        index_document = index_path.read_text(encoding="utf-8")
        injected = index_document.replace(
            "</head>",
            (
                '<meta name="agent-web-daemon-token" content="'
                + escape(token, quote=True)
                + '"></head>'
            ),
            1,
        )
        if (assets / "assets").is_dir():
            app.mount(
                "/assets",
                StaticFiles(directory=assets / "assets"),
                name="ui-assets",
            )

        @app.get("/", include_in_schema=False)
        async def ui() -> HTMLResponse:
            return HTMLResponse(injected)
    else:
        @app.get("/")
        async def missing_ui() -> FileResponse:
            raise HTTPException(
                503,
                "graphical assets are not built; run the browser UI build",
            )

    app.state.browser_daemon = daemon
    return app


async def _safe(awaitable: Any) -> dict[str, Any]:
    try:
        return await awaitable
    except WebActionConfirmationRequired as exc:
        raise HTTPException(409, str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except (ConnectionError, ResourceTrustError, RuntimeError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc


def _https_url(value: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("discovery URL must use absolute HTTPS")


def _default_static_dir() -> Path:
    return Path(__file__).resolve().parent / "static"
