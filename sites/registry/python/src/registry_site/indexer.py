"""Bounded, proof-verifying crawler for the Agent Web registry."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import jcs
from libagentweb import AgentBrowser

from .store import RegistryStore


class RegistryIndexer:
    """Fetch one site completely before atomically replacing its index."""

    def __init__(
        self,
        store: RegistryStore,
        *,
        did_document_path: str | Path,
        private_key_path: str | Path,
        allow_private_networks: bool = False,
        timeout: float = 8.0,
        max_total_bytes: int = 32 * 1024 * 1024,
    ) -> None:
        self.store = store
        self.did_document_path = Path(did_document_path)
        self.private_key_path = Path(private_key_path)
        self.allow_private_networks = allow_private_networks
        self.timeout = timeout
        if max_total_bytes < 1024 * 1024:
            raise ValueError("max_total_bytes must be at least 1 MiB")
        self.max_total_bytes = max_total_bytes

    def index(
        self,
        agent_description_url: str,
        *,
        max_resources: int = 100,
    ) -> dict[str, Any]:
        if max_resources < 1 or max_resources > 100:
            raise ValueError("max_resources must be between 1 and 100")
        browser = AgentBrowser(
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
            ) or browser.open(resource_url)
            if _origin(resource_url) != origin:
                raise ValueError("publisher resource escaped its Agent Description origin")
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
        }


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
