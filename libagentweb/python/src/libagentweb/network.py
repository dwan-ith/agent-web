"""Bounded HTTPS transport with DNS-policy-to-connection pinning."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ipaddress
import json
import socket
from typing import Any, Awaitable, Callable, Mapping, Sequence
from urllib.parse import urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver, ResolveResult


AddressLookup = Callable[[str, int], Awaitable[Sequence[tuple[Any, ...]]]]


@dataclass(frozen=True, slots=True)
class JsonResponse:
    status: int
    headers: dict[str, str]
    document: dict[str, Any]


class NetworkPolicyError(ValueError):
    """A URL or resolved address violates the Agent Web egress policy."""


class PinnedResolver(AbstractResolver):
    """Resolve one hostname only to the addresses already policy-checked."""

    def __init__(self, hostname: str, addresses: Sequence[ResolveResult]) -> None:
        self.hostname = hostname.lower()
        self.addresses = tuple(addresses)

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ) -> list[ResolveResult]:
        if host.lower() != self.hostname:
            raise OSError("pinned resolver refused an unexpected hostname")
        return [
            {**address, "port": port}
            for address in self.addresses
            if family in {socket.AF_UNSPEC, address["family"]}
        ]

    async def close(self) -> None:
        return None


async def resolve_pinned_addresses(
    hostname: str,
    port: int,
    *,
    allow_private_networks: bool,
    lookup: AddressLookup | None = None,
) -> list[ResolveResult]:
    """Resolve once and reject the whole answer if any address is non-global."""

    if lookup is None:
        async def system_lookup(host: str, target_port: int) -> Sequence[tuple[Any, ...]]:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(
                    host,
                    target_port,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                ),
            )

        lookup = system_lookup
    raw_addresses = await lookup(hostname, port)
    pinned: list[ResolveResult] = []
    seen: set[tuple[int, str]] = set()
    for family, socktype, protocol, _canonical, socket_address in raw_addresses:
        value = str(socket_address[0])
        ip = ipaddress.ip_address(value.split("%", 1)[0])
        if not allow_private_networks and not ip.is_global:
            raise NetworkPolicyError(
                f"non-global network address is blocked: {ip}"
            )
        key = (int(family), value)
        if key in seen:
            continue
        seen.add(key)
        pinned.append(
            ResolveResult(
                hostname=hostname,
                host=value,
                port=port,
                family=int(family),
                proto=int(protocol),
                flags=socket.AI_NUMERICHOST,
            )
        )
    if not pinned:
        raise NetworkPolicyError("DNS resolution returned no usable addresses")
    return pinned


async def request_json(
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 8.0,
    max_response_bytes: int = 2 * 1024 * 1024,
    allow_private_networks: bool = False,
) -> JsonResponse:
    """Make one no-redirect HTTPS request on a DNS-pinned connection."""

    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname is None or not parsed.netloc:
        raise NetworkPolicyError("Agent Web requests require an absolute HTTPS URL")
    if parsed.username or parsed.password:
        raise NetworkPolicyError("Agent Web URLs must not contain user information")
    port = parsed.port or 443
    pinned = await resolve_pinned_addresses(
        parsed.hostname,
        port,
        allow_private_networks=allow_private_networks,
    )
    resolver = PinnedResolver(parsed.hostname, pinned)
    connector = aiohttp.TCPConnector(
        resolver=resolver,
        family=socket.AF_UNSPEC,
        use_dns_cache=True,
        ttl_dns_cache=None,
    )
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    try:
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=client_timeout,
        ) as session:
            async with session.request(
                method,
                url,
                headers=dict(headers or {}),
                data=body,
                allow_redirects=False,
            ) as response:
                advertised = response.headers.get("content-length")
                if advertised is not None and int(advertised) > max_response_bytes:
                    raise NetworkPolicyError("Agent Web response exceeded the byte limit")
                content = bytearray()
                async for chunk in response.content.iter_chunked(64 * 1024):
                    content.extend(chunk)
                    if len(content) > max_response_bytes:
                        raise NetworkPolicyError(
                            "Agent Web response exceeded the byte limit"
                        )
                response_headers = dict(response.headers)
                status = response.status
    except aiohttp.ClientError as exc:
        raise ConnectionError(f"Agent Web HTTPS request failed: {exc}") from exc
    try:
        document = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Agent Web response is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ValueError("Agent Web response must be a JSON object")
    return JsonResponse(status=status, headers=response_headers, document=document)
