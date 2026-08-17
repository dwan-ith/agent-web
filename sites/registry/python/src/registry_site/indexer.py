"""Bounded, proof-verifying crawler for the Agent Web registry."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import jcs
from libagentweb import WebAgentBrowser

from .store import RegistryStore


class RegistryIndexer:
    """Fetch one site completely before atomically replacing its index."""

    def __init__(
        self,
        store: RegistryStore,
        *,
        did_document_path: str | Path | None = None,
        private_key_path: str | Path | None = None,
        allow_private_networks: bool = False,
        timeout: float = 8.0,
        max_total_bytes: int = 32 * 1024 * 1024,
        web_browser_factory: Callable[..., Any] = WebAgentBrowser,
        anp_browser_factory: Callable[..., Any] | None = None,
    ) -> None:
        self.store = store
        self.did_document_path = (
            Path(did_document_path) if did_document_path is not None else None
        )
        self.private_key_path = (
            Path(private_key_path) if private_key_path is not None else None
        )
        self.allow_private_networks = allow_private_networks
        self.timeout = timeout
        self.web_browser_factory = web_browser_factory
        self.anp_browser_factory = anp_browser_factory
        if max_total_bytes < 1024 * 1024:
            raise ValueError("max_total_bytes must be at least 1 MiB")
        self.max_total_bytes = max_total_bytes

    def index(
        self,
        discovery_url: str,
        *,
        max_resources: int = 100,
    ) -> dict[str, Any]:
        if max_resources < 1 or max_resources > 100:
            raise ValueError("max_resources must be between 1 and 100")
        parsed = urlsplit(discovery_url)
        if parsed.path == "/.well-known/agent-web" and not parsed.query and not parsed.fragment:
            return asyncio.run(
                self._index_web(discovery_url, max_resources=max_resources)
            )
        if parsed.path == "/.well-known/agent-web":
            raise ValueError("Agent Web discovery URL must not contain query or fragment")
        return self._index_anp(discovery_url, max_resources=max_resources)

    async def _index_web(
        self,
        discovery_url: str,
        *,
        max_resources: int,
    ) -> dict[str, Any]:
        browser = self.web_browser_factory(
            discovery_url,
            timeout=self.timeout,
            max_response_bytes=min(1024 * 1024, self.max_total_bytes),
            allow_private_networks=self.allow_private_networks,
        )
        discovery = await browser.discover()
        publisher = discovery["publisher"]
        origin = _origin(discovery_url)
        entry = await browser.open_entrypoint()

        async def open_resource(url: str) -> dict[str, Any]:
            return await browser.open(url)

        resources = await self._crawl(
            origin=origin,
            publisher=publisher,
            entry=entry,
            open_resource=open_resource,
            max_resources=max_resources,
        )
        descriptor = {
            **discovery,
            "name": discovery.get("name") or entry["name"],
            "description": (
                discovery.get("description")
                or entry.get("description", "Agent Web publisher")
            ),
        }
        count = self.store.replace_verified_site(
            discovery_url=discovery_url,
            description=descriptor,
            resources=resources,
        )
        return {
            "discoveryUrl": discovery_url,
            "publisher": publisher,
            "resourcesIndexed": count,
            "verification": (
                "HTTPS origin discovery, authorized key, resource proof, "
                "canonical URL, expiry"
            ),
            "binding": "Agent Web",
        }

    def _index_anp(
        self,
        agent_description_url: str,
        *,
        max_resources: int,
    ) -> dict[str, Any]:
        if self.did_document_path is None or self.private_key_path is None:
            raise ValueError("ANP indexing requires browser DID and private key files")
        if self.anp_browser_factory is None:
            from libagentweb import AgentBrowser

            browser_factory = AgentBrowser
        else:
            browser_factory = self.anp_browser_factory

        browser = browser_factory(
            agent_description_url,
            did_document_path=self.did_document_path,
            private_key_path=self.private_key_path,
            timeout=self.timeout,
            max_response_bytes=min(1024 * 1024, self.max_total_bytes),
            allow_private_networks=self.allow_private_networks,
        )
        description = browser.discover()
        publisher = description["identifier"]
        origin = _origin(agent_description_url)
        entry = browser.open_entrypoint()
        resources = asyncio.run(
            self._crawl(
                origin=origin,
                publisher=publisher,
                entry=entry,
                open_resource=lambda url: asyncio.to_thread(browser.open, url),
                max_resources=max_resources,
            )
        )
        count = self.store.replace_verified_site(
            agent_description_url=agent_description_url,
            description=description,
            resources=resources,
        )
        return {
            "agentDescription": agent_description_url,
            "publisher": publisher,
            "resourcesIndexed": count,
            "verification": (
                "DID-WBA binding, Agent Description proof, resource proof, "
                "canonical URL, expiry"
            ),
            "binding": "ANP compatibility",
        }

    async def _crawl(
        self,
        *,
        origin: str,
        publisher: str,
        entry: dict[str, Any],
        open_resource: Any,
        max_resources: int,
    ) -> list[dict[str, Any]]:
        queue = [entry["@id"]]
        prefetched = {entry["@id"]: entry}
        visited: set[str] = set()
        resources: list[dict[str, Any]] = []
        total_bytes = 0
        while queue:
            resource_url = queue.pop(0)
            if resource_url in visited:
                continue
            if len(visited) >= max_resources:
                raise RuntimeError("registry crawl exceeded its resource limit")
            resource = prefetched.pop(
                resource_url,
                None,
            ) or await open_resource(resource_url)
            if _origin(resource_url) != origin:
                raise ValueError("publisher resource escaped its discovery origin")
            if resource["provenance"]["publisher"] != publisher:
                raise ValueError("publisher site linked a different publisher as content")
            total_bytes += len(jcs.canonicalize(resource))
            if total_bytes > self.max_total_bytes:
                raise RuntimeError("registry crawl exceeded its total byte limit")
            visited.add(resource_url)
            resources.append(resource)
            for link in resource["links"]:
                if link["rel"] not in {"item", "next"}:
                    continue
                target = link["href"]
                if target not in visited:
                    if _origin(target) != origin:
                        raise ValueError("publisher content link escaped its origin")
                    queue.append(target)
        return resources


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("registry targets must be absolute HTTPS URLs")
    port = parsed.port
    default = 443
    authority = parsed.hostname.lower() if port in {None, default} else (
        f"{parsed.hostname.lower()}:{port}"
    )
    return f"https://{authority}"
