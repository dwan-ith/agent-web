"""A Web-native Agent Browser with no ANP runtime dependency."""

from __future__ import annotations

from copy import deepcopy
import json
from typing import Any, Awaitable, Callable, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from jsonschema import Draft202012Validator

from .discovery import validate_discovery_document
from .identity import ResourceTrustError, verify_resource
from .http_signatures import HTTP_SIGNATURE_SECURITY, sign_agent_web_request
from .network import request_json
from .resource import RESOURCE_MEDIA_TYPE, validate_resource
from .signing import Ed25519Signer


DocumentFetcher = Callable[[str], Awaitable[Mapping[str, Any]]]
ActionFetcher = Callable[[str, str, Mapping[str, Any]], Awaitable[Mapping[str, Any]]]


class WebActionConfirmationRequired(PermissionError):
    """An advertised action requires explicit interactive confirmation."""


class WebAgentBrowser:
    """Discover and navigate signed Agent Web resources over HTTPS alone."""

    def __init__(
        self,
        discovery_url: str,
        *,
        timeout: float = 8.0,
        max_response_bytes: int = 2 * 1024 * 1024,
        allowed_origins: set[str] | None = None,
        allow_private_networks: bool = False,
        fetch_document: DocumentFetcher | None = None,
        fetch_action: ActionFetcher | None = None,
        caller_controller: str | None = None,
        caller_signer: Ed25519Signer | None = None,
    ) -> None:
        self.discovery_url = discovery_url
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.allow_private_networks = allow_private_networks
        self.allowed_origins = {_origin(discovery_url)} | set(allowed_origins or ())
        self._fetch_document = fetch_document
        self._fetch_action = fetch_action
        if (caller_controller is None) != (caller_signer is None):
            raise ValueError("caller_controller and caller_signer must be configured together")
        self.caller_controller = caller_controller
        self.caller_signer = caller_signer
        self._discovery: dict[str, Any] | None = None
        self._current_resource: dict[str, Any] | None = None

    async def discover(self) -> dict[str, Any]:
        document = await self._get_json(self.discovery_url, discovery=True)
        self._discovery = validate_discovery_document(
            document,
            discovery_url=self.discovery_url,
        )
        return deepcopy(self._discovery)

    async def open_entrypoint(self) -> dict[str, Any]:
        discovery = self._discovery or await self.discover()
        return await self.open(str(discovery["agentWeb"]["entryPoint"]))

    async def open(self, resource_url: str) -> dict[str, Any]:
        discovery = self._discovery or await self.discover()
        document = validate_resource(await self._get_json(resource_url))
        if document["@id"] != resource_url:
            raise ResourceTrustError("resource @id does not match its transport URL")
        if document["provenance"]["publisher"] != discovery["publisher"]:
            raise ResourceTrustError("resource publisher differs from Web discovery")
        verified = verify_resource(
            document,
            controller_document=discovery,
            reject_expired=True,
        )
        self._current_resource = deepcopy(verified)
        return verified

    async def invoke(
        self,
        action_name: str,
        params: Mapping[str, Any],
        *,
        confirmed: bool = False,
        resource_url: str | None = None,
    ) -> dict[str, Any]:
        """Invoke one HTTP affordance advertised by a verified resource."""

        if resource_url is not None:
            resource = await self.open(resource_url)
        elif self._current_resource is not None:
            resource = deepcopy(self._current_resource)
        else:
            raise ValueError("open a resource before invoking an action")
        actions = resource.get("affordances", {}).get("actions", {})
        action = actions.get(action_name) if isinstance(actions, Mapping) else None
        if not isinstance(action, Mapping):
            raise ValueError(f"action '{action_name}' is not advertised")
        if action.get("authorizationLevel") == "user-presence-required" and not confirmed:
            raise WebActionConfirmationRequired(
                f"action '{action_name}' requires explicit user presence"
            )
        errors = sorted(
            Draft202012Validator(action["input"]).iter_errors(dict(params)),
            key=lambda error: list(error.path),
        )
        if errors:
            details = "; ".join(
                f"{'/'.join(map(str, error.path)) or '<root>'}: {error.message}"
                for error in errors
            )
            raise ValueError(f"action input is invalid: {details}")
        interfaces = [
            value
            for value in action.get("interfaces", [])
            if isinstance(value, Mapping) and value.get("protocol") == "HTTP"
        ]
        if len(interfaces) != 1:
            raise ValueError(
                f"action '{action_name}' must advertise exactly one HTTP interface"
            )
        interface = interfaces[0]
        url = str(interface["href"])
        if _origin(url) not in self.allowed_origins:
            raise ResourceTrustError("action origin is outside browser policy")
        method = str(interface.get("method", "POST")).upper()
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("HTTP action advertises an unsupported method")
        if action.get("safe") is True and method not in {"GET", "HEAD"}:
            raise ValueError("safe action is bound to an unsafe HTTP method")
        security = str(interface.get("security", "none"))
        if security == HTTP_SIGNATURE_SECURITY and (
            self.caller_controller is None or self.caller_signer is None
        ):
            raise PermissionError(
                "action requires an authenticated Agent Web caller identity"
            )
        if security not in {"none", HTTP_SIGNATURE_SECURITY}:
            raise ValueError("HTTP action advertises an unsupported security profile")
        if security == HTTP_SIGNATURE_SECURITY and self._fetch_action is not None:
            raise ValueError(
                "custom action fetchers cannot execute authenticated HTTP actions"
            )

        if self._fetch_action is not None:
            response_document = deepcopy(
                dict(await self._fetch_action(method, url, dict(params)))
            )
        else:
            request_url = url
            body: bytes | None = None
            headers = {"Accept": RESOURCE_MEDIA_TYPE}
            if method in {"GET", "HEAD"}:
                request_url = _append_query(url, params)
            else:
                content_type = str(interface.get("contentType", "application/json"))
                if content_type != "application/json":
                    raise ValueError("Web-native browser supports JSON HTTP actions only")
                body = json.dumps(
                    dict(params), ensure_ascii=False, separators=(",", ":"), sort_keys=True
                ).encode("utf-8")
                headers["Content-Type"] = content_type
            if security == HTTP_SIGNATURE_SECURITY:
                headers.update(
                    sign_agent_web_request(
                        method=method,
                        target_uri=request_url,
                        body=body or b"",
                        content_type=str(interface.get("contentType", "application/json")),
                        caller=self.caller_controller,
                        signer=self.caller_signer,
                    )
                )
            response = await request_json(
                request_url,
                method=method,
                headers=headers,
                body=body,
                timeout=self.timeout,
                max_response_bytes=self.max_response_bytes,
                allow_private_networks=self.allow_private_networks,
            )
            if response.status < 200 or response.status >= 300:
                raise ConnectionError(
                    f"Agent Web action returned HTTP {response.status}"
                )
            response_document = response.document

        discovery = self._discovery or await self.discover()
        document = validate_resource(response_document)
        if document["provenance"]["publisher"] != discovery["publisher"]:
            raise ResourceTrustError("action result publisher differs from Web discovery")
        verified = verify_resource(
            document,
            controller_document=discovery,
            reject_expired=True,
        )
        self._current_resource = deepcopy(verified)
        return verified

    async def _get_json(self, url: str, *, discovery: bool = False) -> dict[str, Any]:
        if _origin(url) not in self.allowed_origins:
            raise ResourceTrustError("URL origin is outside browser policy")
        if self._fetch_document is not None:
            return deepcopy(dict(await self._fetch_document(url)))
        accept = (
            "application/agent-web-discovery+json, application/json"
            if discovery
            else f"{RESOURCE_MEDIA_TYPE}, application/json"
        )
        response = await request_json(
            url,
            headers={"Accept": accept},
            timeout=self.timeout,
            max_response_bytes=self.max_response_bytes,
            allow_private_networks=self.allow_private_networks,
        )
        if response.status != 200:
            raise ConnectionError(f"Agent Web endpoint returned HTTP {response.status}")
        return response.document


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.fragment:
        raise ValueError("Agent Web browser URLs must be absolute HTTPS URLs")
    authority = parsed.hostname.lower()
    if parsed.port is not None and parsed.port != 443:
        authority = f"{authority}:{parsed.port}"
    return f"https://{authority}"


def _append_query(url: str, params: Mapping[str, Any]) -> str:
    parsed = urlsplit(url)
    existing = parse_qsl(parsed.query, keep_blank_values=True)
    occupied = {key for key, _value in existing}
    if occupied.intersection(params):
        raise ValueError("action parameters conflict with fixed interface query")
    query_items = list(existing)
    for key, value in params.items():
        if not isinstance(key, str):
            raise ValueError("action parameter names must be strings")
        values = value if isinstance(value, list) else [value]
        for item in values:
            if item is None or isinstance(item, (dict, list)):
                raise ValueError("GET action parameters must be scalar values")
            if isinstance(item, bool):
                encoded = "true" if item else "false"
            else:
                encoded = str(item)
            query_items.append((key, encoded))
    return urlunsplit(parsed._replace(query=urlencode(query_items, doseq=True)))
