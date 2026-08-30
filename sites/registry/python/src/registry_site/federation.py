"""Non-transitive federation between independently operated Agent Web registries."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
from pathlib import Path
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
    feedUrl: str | None = None
    feedGeneration: int | None = None
    skippedReason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "peer": self.peer,
            "sourcesAdvertised": self.sourcesAdvertised,
            "sourcesIndexed": self.sourcesIndexed,
            "resourcesIndexed": self.resourcesIndexed,
            "failures": list(self.failures),
            "trust": self.trust,
            "feedUrl": self.feedUrl,
            "feedGeneration": self.feedGeneration,
            "skippedReason": self.skippedReason,
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
        known_generations: dict[str, int] | None = None,
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
                known_generations=known_generations,
            )
        ).as_dict()

    async def _sync(
        self,
        peer_discovery_url: str,
        *,
        max_sources: int,
        max_resources_per_source: int,
        continue_on_error: bool,
        known_generations: dict[str, int] | None,
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
        generation = data.get("feedGeneration")
        if generation is not None and (
            isinstance(generation, bool)
            or not isinstance(generation, int)
            or generation < 0
        ):
            raise ValueError("peer feed generation is invalid")
        if (
            known_generations is not None
            and generation is not None
            and known_generations.get(feed_url) == generation
            and generation > 0
        ):
            # Incremental convergence: the peer's signed feed still carries
            # the generation we already converged to, so no work this round.
            return FederationSyncResult(
                peer=str(discovery["publisher"]),
                sourcesAdvertised=0,
                sourcesIndexed=0,
                resourcesIndexed=0,
                failures=(),
                feedUrl=feed_url,
                feedGeneration=int(generation),
                skippedReason="feed-generation-unchanged",
            )
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
        # Verify original sources concurrently (bounded): each source runs in
        # its own thread with its own event loop via RegistryIndexer, and the
        # store serializes snapshots. Results stay in feed order regardless
        # of completion order.
        semaphore = asyncio.Semaphore(4)

        async def verify_source(url: str) -> int:
            async with semaphore:
                result = await asyncio.to_thread(
                    self.indexer.index,
                    url,
                    max_resources=max_resources_per_source,
                )
                return int(result["resourcesIndexed"])

        outcomes = await asyncio.gather(
            *(verify_source(url) for url in urls), return_exceptions=True
        )
        for url, outcome in zip(urls, outcomes):
            if isinstance(outcome, BaseException):
                failures.append({"discoveryUrl": url, "error": str(outcome)})
                if not continue_on_error:
                    raise outcome
            else:
                indexed += 1
                resources += outcome
        return FederationSyncResult(
            peer=str(discovery["publisher"]),
            sourcesAdvertised=len(urls),
            sourcesIndexed=indexed,
            resourcesIndexed=resources,
            failures=tuple(failures),
            feedUrl=feed_url,
            feedGeneration=(
                None if generation is None else int(generation)
            ),
        )


def _types(resource: dict[str, Any]) -> set[str]:
    value = resource.get("@type", [])
    return {value} if isinstance(value, str) else set(value)


class FederationStateFile:
    """Durable record of converged feed generations, keyed by feed URL."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def load(self) -> dict[str, int]:
        try:
            document = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        if not isinstance(document, dict):
            raise ValueError("federation state file must contain a JSON object")
        state: dict[str, int] = {}
        for url, generation in document.items():
            if (
                not isinstance(url, str)
                or isinstance(generation, bool)
                or not isinstance(generation, int)
                or generation < 0
            ):
                raise ValueError("federation state file entries are invalid")
            state[url] = generation
        return state

    def store(self, state: dict[str, int]) -> None:
        cleaned = {
            str(url): int(generation)
            for url, generation in state.items()
            if int(generation) >= 0
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_suffix(self._path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(cleaned, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(self._path)


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
