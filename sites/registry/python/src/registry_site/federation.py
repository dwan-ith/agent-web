"""Non-transitive federation between independently operated Agent Web registries."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

from libagentweb import WebAgentBrowser

from .indexer import RegistryIndexer


@dataclass(frozen=True, slots=True)
class FederationSyncResult:
    peer: str
    sourcesAdvertised: int
    sourcesIndexed: int
    resourcesIndexed: int
    failures: tuple[dict[str, str], ...]
    trust: str = "independent-source-reverification"

    def as_dict(self) -> dict[str, Any]:
        return {
            "peer": self.peer,
            "sourcesAdvertised": self.sourcesAdvertised,
            "sourcesIndexed": self.sourcesIndexed,
            "resourcesIndexed": self.resourcesIndexed,
            "failures": list(self.failures),
            "trust": self.trust,
        }


class RegistryFederator:
    """Read a verified peer hint feed, then verify every original source again."""

    def __init__(
        self,
        indexer: RegistryIndexer,
        *,
        allow_private_networks: bool = False,
        timeout: float = 8.0,
        browser_factory: Callable[..., Any] = WebAgentBrowser,
    ) -> None:
        self.indexer = indexer
        self.allow_private_networks = allow_private_networks
        self.timeout = timeout
        self.browser_factory = browser_factory

    def sync(
        self,
        peer_discovery_url: str,
        *,
        max_sources: int = 100,
        max_resources_per_source: int = 100,
        continue_on_error: bool = True,
    ) -> dict[str, Any]:
        if max_sources < 1 or max_sources > 1000:
            raise ValueError("max_sources must be between 1 and 1000")
        if max_resources_per_source < 1 or max_resources_per_source > 100:
            raise ValueError("max_resources_per_source must be between 1 and 100")
        return asyncio.run(
            self._sync(
                peer_discovery_url,
                max_sources=max_sources,
                max_resources_per_source=max_resources_per_source,
                continue_on_error=continue_on_error,
            )
        ).as_dict()

    async def _sync(
        self,
        peer_discovery_url: str,
        *,
        max_sources: int,
        max_resources_per_source: int,
        continue_on_error: bool,
    ) -> FederationSyncResult:
        peer_discovery_url = _canonical_discovery_url(peer_discovery_url)
        browser = self.browser_factory(
            peer_discovery_url,
            timeout=self.timeout,
            allow_private_networks=self.allow_private_networks,
        )
        discovery = await browser.discover()
        entry = await browser.open_entrypoint()
        feed_links = [
            link for link in entry["links"]
            if link["rel"] == "registry-federation"
        ]
        if len(feed_links) != 1:
            raise ValueError("peer must advertise exactly one registry-federation link")
        feed_link = feed_links[0]
        if feed_link.get("mediaType") != "application/agent-web+json":
            raise ValueError("peer federation link has the wrong media type")
        feed_url = str(feed_link["href"])
        # WebAgentBrowser.open returns only schema-valid, canonical, signed,
        # discovery-authorized resources. Alternate factories must honor that
        # same contract.
        feed = await browser.open(feed_url)
        if "RegistrySourceFeed" not in _types(feed):
            raise ValueError("peer did not publish a RegistrySourceFeed")
        data = feed.get("data")
        if not isinstance(data, dict) or data.get("transitiveTrust") is not False:
            raise ValueError("peer feed does not reject transitive trust")
        extension = feed.get("extensions", {}).get("registryFederation", {})
        if extension.get("profile") != "urn:agent-web:registry-federation:0.1":
            raise ValueError("peer feed uses an unsupported federation profile")
        if extension.get("containsAssertions") is not False:
            raise ValueError("peer feed claims to contain source assertions")
        sources = [
            link for link in feed["links"]
            if link["rel"] == "source"
        ]
        if len(sources) > max_sources:
            raise RuntimeError("peer federation feed exceeded its source limit")
        if data.get("sourceCount") != len(sources):
            raise ValueError("peer federation source count is inconsistent")
        urls: list[str] = []
        seen: set[str] = set()
        for link in sources:
            url = str(link["href"])
            try:
                canonical = _canonical_discovery_url(url)
            except ValueError as exc:
                raise ValueError("federation source must be Web-native discovery") from exc
            if link.get("mediaType") != "application/agent-web-discovery+json":
                raise ValueError("federation source has the wrong media type")
            if canonical == peer_discovery_url:
                raise ValueError("peer registry cannot advertise itself as source content")
            if canonical in seen:
                raise ValueError("peer federation feed contains a duplicate source")
            seen.add(canonical)
            urls.append(canonical)

        indexed = 0
        resources = 0
        failures: list[dict[str, str]] = []
        for url in urls:
            try:
                # Run synchronously only after the peer feed has been fully
                # verified and bounded. RegistryIndexer re-fetches discovery
                # and verifies the original publisher's resource graph.
                result = await asyncio.to_thread(
                    self.indexer.index,
                    url,
                    max_resources=max_resources_per_source,
                )
                indexed += 1
                resources += int(result["resourcesIndexed"])
            except Exception as exc:
                failures.append({"discoveryUrl": url, "error": str(exc)})
                if not continue_on_error:
                    raise
        return FederationSyncResult(
            peer=str(discovery["publisher"]),
            sourcesAdvertised=len(urls),
            sourcesIndexed=indexed,
            resourcesIndexed=resources,
            failures=tuple(failures),
        )


def _types(resource: dict[str, Any]) -> set[str]:
    value = resource.get("@type", [])
    return {value} if isinstance(value, str) else set(value)


def _canonical_discovery_url(url: str) -> str:
    parsed = urlsplit(url)
    if not (
        parsed.scheme.lower() == "https"
        and parsed.hostname
        and not parsed.username
        and not parsed.password
        and parsed.path == "/.well-known/agent-web"
        and not parsed.query
        and not parsed.fragment
    ):
        raise ValueError("URL is not canonical Agent Web discovery")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    authority = host if parsed.port in {None, 443} else f"{host}:{parsed.port}"
    return f"https://{authority}/.well-known/agent-web"
