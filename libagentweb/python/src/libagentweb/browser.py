"""A proof-verifying Agent Browser built on official ANP SDK primitives."""

from __future__ import annotations

import asyncio
from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit
from uuid import uuid4

from anp.authentication import DIDWbaAuthHeader
from anp.authentication.did_resolver import build_did_resolution_url
from anp.authentication.did_wba import validate_did_document_binding
from anp.openanp.client import parse_agent_document, parse_openrpc
from anp.proof.object_proof import ObjectProofError, verify_object_proof

from .identity import ResourceTrustError, verify_resource
from .network import request_json
from .resource import RESOURCE_MEDIA_TYPE, validate_resource
from .wns import DidResolver, DocumentFetcher, ResolvedHandle, resolve_exact_handle


class RemoteANPError(RuntimeError):
    """A safe wrapper around remote ANP discovery or invocation failures."""


class ActionConfirmationRequired(PermissionError):
    """A state-changing action requires explicit user presence."""


class AgentBrowser:
    """Discover, verify, navigate, and invoke live Agent Web publishers."""

    def __init__(
        self,
        agent_description_url: str,
        *,
        did_document_path: str | Path | None = None,
        private_key_path: str | Path | None = None,
        auth_header: DIDWbaAuthHeader | None = None,
        timeout: float = 8.0,
        max_response_bytes: int = 2 * 1024 * 1024,
        allowed_origins: set[str] | None = None,
        allow_private_networks: bool = False,
    ) -> None:
        self.agent_description_url = agent_description_url
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.allow_private_networks = allow_private_networks
        description_origin = _origin(agent_description_url)
        self.allowed_origins = {description_origin} | set(allowed_origins or ())
        if auth_header is not None:
            if did_document_path is not None or private_key_path is not None:
                raise ValueError(
                    "auth_header cannot be combined with identity key paths"
                )
            self.auth = auth_header
        else:
            if did_document_path is None or private_key_path is None:
                raise ValueError(
                    "provide auth_header or both DID and private-key paths"
                )
            self.auth = DIDWbaAuthHeader(
                did_document_path=str(did_document_path),
                private_key_path=str(private_key_path),
                auth_mode="http_signatures",
            )
        self._description: dict[str, Any] | None = None
        self._method_urls: dict[str, str] = {}
        self._handle_binding: ResolvedHandle | None = None

    @property
    def handle_binding(self) -> ResolvedHandle | None:
        return deepcopy(self._handle_binding)

    @classmethod
    def from_handle(
        cls,
        handle: str,
        *,
        did_document_path: str | Path | None = None,
        private_key_path: str | Path | None = None,
        auth_header: DIDWbaAuthHeader | None = None,
        minimum_binding_generation: str | None = None,
        timeout: float = 8.0,
        max_response_bytes: int = 2 * 1024 * 1024,
        allow_private_networks: bool = False,
    ) -> "AgentBrowser":
        return _run(
            cls.from_handle_async(
                handle,
                did_document_path=did_document_path,
                private_key_path=private_key_path,
                auth_header=auth_header,
                minimum_binding_generation=minimum_binding_generation,
                timeout=timeout,
                max_response_bytes=max_response_bytes,
                allow_private_networks=allow_private_networks,
            )
        )

    @classmethod
    async def from_handle_async(
        cls,
        handle: str,
        *,
        did_document_path: str | Path | None = None,
        private_key_path: str | Path | None = None,
        auth_header: DIDWbaAuthHeader | None = None,
        minimum_binding_generation: str | None = None,
        timeout: float = 8.0,
        max_response_bytes: int = 2 * 1024 * 1024,
        allow_private_networks: bool = False,
        fetch_document: DocumentFetcher | None = None,
        did_resolver: DidResolver | None = None,
    ) -> "AgentBrowser":
        """Construct a browser only after exact WNS handle verification."""

        binding = await resolve_exact_handle(
            handle,
            timeout=timeout,
            max_response_bytes=max_response_bytes,
            minimum_binding_generation=minimum_binding_generation,
            allow_private_networks=allow_private_networks,
            fetch_document=fetch_document,
            did_resolver=did_resolver,
        )
        endpoints = {
            service.get("serviceEndpoint")
            for service in binding.did_document.get("service", [])
            if isinstance(service, Mapping)
            and service.get("type") == "AgentDescription"
            and isinstance(service.get("serviceEndpoint"), str)
        }
        if len(endpoints) != 1:
            raise ResourceTrustError(
                "WNS DID must authorize exactly one Agent Description endpoint"
            )
        browser = cls(
            endpoints.pop(),
            did_document_path=did_document_path,
            private_key_path=private_key_path,
            auth_header=auth_header,
            timeout=timeout,
            max_response_bytes=max_response_bytes,
            allow_private_networks=allow_private_networks,
        )
        browser._handle_binding = binding
        return browser

    def discover(self) -> dict[str, Any]:
        return _run(self.discover_async())

    async def discover_async(self) -> dict[str, Any]:
        """Verify the AD's DID binding, service binding, and object proof."""

        await self._ensure_allowed_url(self.agent_description_url)
        description = await self._get_json(self.agent_description_url)
        publisher = description.get("identifier")
        if not isinstance(publisher, str) or not publisher.startswith("did:wba:"):
            raise ResourceTrustError("Agent Description has no DID-WBA identifier")
        did_url = build_did_resolution_url(publisher)
        if _origin(did_url) != _origin(self.agent_description_url):
            raise ResourceTrustError(
                "Agent Description DID is not bound to its HTTPS origin"
            )
        await self._ensure_allowed_url(did_url)
        try:
            did_document = await self._get_json(did_url)
            if not validate_did_document_binding(did_document, verify_proof=True):
                raise ValueError("DID-WBA document has an invalid proof or key binding")
            verify_object_proof(
                description,
                issuer_did=publisher,
                issuer_did_document=did_document,
            )
        except (ObjectProofError, ValueError, ConnectionError) as exc:
            raise ResourceTrustError(
                f"Agent Description trust verification failed: {exc}"
            ) from exc
        endpoints = {
            service.get("serviceEndpoint")
            for service in did_document.get("service", [])
            if isinstance(service, Mapping)
            and service.get("type") == "AgentDescription"
        }
        if self.agent_description_url not in endpoints:
            raise ResourceTrustError(
                "DID document does not authorize this Agent Description URL"
            )
        self._method_urls = await self._discover_method_urls(description)
        self._description = deepcopy(description)
        return deepcopy(description)

    def open(self, resource_url: str) -> dict[str, Any]:
        return _run(self.open_async(resource_url))

    async def open_async(self, resource_url: str) -> dict[str, Any]:
        await self._ensure_allowed_url(resource_url)
        document = validate_resource(await self._get_json(resource_url))
        return await self._verify_resource_document(
            document,
            transport_url=resource_url,
        )

    async def _verify_resource_document(
        self,
        document: Mapping[str, Any],
        *,
        transport_url: str | None = None,
    ) -> dict[str, Any]:
        document = validate_resource(document)
        resource_url = transport_url or document["@id"]
        await self._ensure_allowed_url(resource_url)
        if document["@id"] != resource_url:
            raise ResourceTrustError(
                "resource @id does not match the URL that returned it"
            )
        publisher = document["provenance"]["publisher"]
        did_url = build_did_resolution_url(publisher)
        await self._ensure_allowed_url(did_url)
        if _origin(did_url) != _origin(resource_url):
            raise ResourceTrustError(
                "resource publisher DID is not bound to the resource origin"
            )
        try:
            did_document = await self._get_json(did_url)
            if not validate_did_document_binding(did_document, verify_proof=True):
                raise ValueError("DID-WBA document has an invalid proof or key binding")
        except Exception as exc:
            raise ResourceTrustError(
                f"publisher DID resolution failed: {exc}"
            ) from exc
        return verify_resource(
            document,
            publisher_did_document=did_document,
            reject_expired=True,
        )

    def open_entrypoint(self) -> dict[str, Any]:
        return _run(self.open_entrypoint_async())

    async def open_entrypoint_async(self) -> dict[str, Any]:
        description = self._description or await self.discover_async()
        try:
            entrypoint = description["agentWeb"]["entryPoint"]
        except (KeyError, TypeError) as exc:
            raise ValueError(
                "Agent Description does not advertise Agent Web"
            ) from exc
        return await self.open_async(str(entrypoint))

    def call(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        *,
        confirmed: bool = False,
        resource_url: str | None = None,
    ) -> Any:
        return _run(
            self.call_async(
                method,
                params,
                confirmed=confirmed,
                resource_url=resource_url,
            )
        )

    async def call_async(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        *,
        confirmed: bool = False,
        resource_url: str | None = None,
    ) -> Any:
        """Invoke only an advertised affordance over pinned ANP transport."""

        action_resource = (
            await self.open_async(resource_url)
            if resource_url is not None
            else await self.open_entrypoint_async()
        )
        action = _action_for_method(action_resource, method)
        if (
            action["authorizationLevel"] == "user-presence-required"
            and not confirmed
        ):
            raise ActionConfirmationRequired(
                f"action '{method}' requires explicit confirmation"
            )
        if not self._method_urls:
            await self.discover_async()
        discovered_rpc = self._method_urls.get(method)
        action_rpc = next(
            (
                interface.get("href")
                for interface in action["interfaces"]
                if interface["protocol"] == "ANP"
                and interface.get("method") == method
            ),
            None,
        )
        if not isinstance(action_rpc, str) or discovered_rpc != action_rpc:
            raise ResourceTrustError(
                f"action '{method}' RPC URL conflicts with ANP discovery"
            )
        await self._ensure_allowed_url(action_rpc)
        result = await self._call_jsonrpc(action_rpc, method, dict(params or {}))
        if not isinstance(result, Mapping):
            raise ResourceTrustError(
                f"ANP action '{method}' did not return a resource object"
            )
        return await self._verify_resource_document(result)

    def traverse(
        self,
        resource_url: str | None = None,
        *,
        max_resources: int = 100,
    ) -> list[dict[str, Any]]:
        return _run(
            self.traverse_async(
                resource_url,
                max_resources=max_resources,
            )
        )

    async def traverse_async(
        self,
        resource_url: str | None = None,
        *,
        max_resources: int = 100,
    ) -> list[dict[str, Any]]:
        if max_resources < 1:
            raise ValueError("max_resources must be positive")
        if resource_url is None:
            resource_url = (await self.open_entrypoint_async())["@id"]
        queue = [resource_url]
        visited: set[str] = set()
        resources: list[dict[str, Any]] = []
        while queue:
            target = queue.pop(0)
            if target in visited:
                continue
            if len(visited) >= max_resources:
                raise RuntimeError("Agent Web traversal exceeded its resource limit")
            resource = await self.open_async(target)
            visited.add(target)
            resources.append(resource)
            for link in resource["links"]:
                if (
                    link["rel"] in {"item", "next", "related"}
                    and link["href"] not in visited
                ):
                    queue.append(link["href"])
        return resources

    async def _get_json(self, url: str) -> dict[str, Any]:
        response = await request_json(
            url,
            headers={
                "Accept": (
                    f"{RESOURCE_MEDIA_TYPE}, application/ld+json, "
                    "application/json"
                )
            },
            timeout=self.timeout,
            max_response_bytes=self.max_response_bytes,
            allow_private_networks=self.allow_private_networks,
        )
        if response.status != 200:
            raise ConnectionError(
                f"Agent Web request failed with HTTP {response.status}: {url}"
            )
        return response.document

    async def _discover_method_urls(
        self,
        description: Mapping[str, Any],
    ) -> dict[str, str]:
        try:
            _, methods = parse_agent_document(dict(description))
            if not methods:
                for value in description.get("interfaces", []):
                    if not isinstance(value, Mapping) or value.get("type") != (
                        "StructuredInterface"
                    ) or value.get("protocol") != "openrpc":
                        continue
                    interface_url = value.get("url")
                    if not isinstance(interface_url, str):
                        continue
                    await self._ensure_allowed_url(interface_url)
                    methods.extend(parse_openrpc(await self._get_json(interface_url)))
            discovered: dict[str, str] = {}
            for method in methods:
                name = method.get("name")
                servers = method.get("servers")
                if not isinstance(name, str) or not isinstance(servers, list) or not servers:
                    raise ValueError("ANP method has no RPC server")
                first = servers[0]
                rpc_url = first.get("url") if isinstance(first, Mapping) else None
                if not isinstance(rpc_url, str):
                    raise ValueError("ANP method RPC server has no URL")
                await self._ensure_allowed_url(rpc_url)
                previous = discovered.setdefault(name, rpc_url)
                if previous != rpc_url:
                    raise ValueError("ANP method is advertised at conflicting RPC URLs")
            if not discovered:
                raise ValueError("Agent Description exposes no callable ANP methods")
            return discovered
        except (TypeError, ValueError, ConnectionError) as exc:
            raise RemoteANPError(f"ANP discovery failed: {exc}") from exc

    async def _call_jsonrpc(
        self,
        rpc_url: str,
        method: str,
        params: Mapping[str, Any],
    ) -> Any:
        request_id = str(uuid4())
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": dict(params),
        }
        body = json.dumps(
            payload,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        base_headers = {"Content-Type": "application/json"}
        headers = dict(base_headers)
        headers.update(
            self.auth.get_auth_header(
                server_url=rpc_url,
                method="POST",
                headers=headers,
                body=body,
            )
        )
        response = await request_json(
            rpc_url,
            method="POST",
            headers=headers,
            body=body,
            timeout=self.timeout,
            max_response_bytes=self.max_response_bytes,
            allow_private_networks=self.allow_private_networks,
        )
        if response.status == 401:
            authorization = _header(headers, "authorization")
            retry = bool(authorization and authorization.lower().startswith("bearer "))
            if retry:
                self.auth.clear_token(rpc_url)
            else:
                retry = self.auth.should_retry_after_401(response.headers)
            if retry:
                headers = dict(base_headers)
                headers.update(
                    self.auth.get_challenge_auth_header(
                        server_url=rpc_url,
                        response_headers=response.headers,
                        method="POST",
                        headers=headers,
                        body=body,
                    )
                )
                response = await request_json(
                    rpc_url,
                    method="POST",
                    headers=headers,
                    body=body,
                    timeout=self.timeout,
                    max_response_bytes=self.max_response_bytes,
                    allow_private_networks=self.allow_private_networks,
                )
        if response.status != 200:
            raise RemoteANPError(
                f"ANP action '{method}' returned HTTP {response.status}"
            )
        self.auth.update_token(rpc_url, response.headers)
        if response.document.get("id") != request_id:
            raise RemoteANPError("ANP JSON-RPC response id does not match the request")
        if "error" in response.document:
            error = response.document["error"]
            raise RemoteANPError(f"ANP action '{method}' failed: {error}")
        if "result" not in response.document:
            raise RemoteANPError("ANP JSON-RPC response has no result")
        return response.document["result"]

    async def _ensure_allowed_url(self, url: str) -> None:
        origin = _origin(url)
        if origin not in self.allowed_origins:
            raise ValueError(f"Origin '{origin}' is not allowed by browser policy")
        parsed = urlsplit(url)
        if parsed.username or parsed.password:
            raise ValueError("Agent Web URLs must not contain user information")
        if parsed.hostname is None:
            raise ValueError("Agent Web URL has no hostname")


def _action_for_method(
    resource: Mapping[str, Any],
    method: str,
) -> dict[str, Any]:
    for action in resource["affordances"]["actions"].values():
        for interface in action["interfaces"]:
            if interface["protocol"] == "ANP" and interface.get("method") == method:
                return action
    raise PermissionError(
        f"ANP method '{method}' is not advertised by the current resource"
    )


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("Agent Web URLs must use absolute HTTPS identifiers")
    return f"https://{parsed.netloc}"


def _header(headers: Mapping[str, str], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


def _run(coroutine: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    coroutine.close()
    raise RuntimeError(
        "synchronous AgentBrowser methods cannot run inside an event loop; "
        "use the matching async method"
    )
