"""Real Open-Meteo bridge with bounded I/O, attribution, and TTL caching."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from typing import Any, Mapping, Protocol
from urllib.parse import urlencode

import httpx


@dataclass(frozen=True, slots=True)
class Location:
    slug: str
    name: str
    latitude: float
    longitude: float


DEFAULT_LOCATIONS = (
    Location("bengaluru", "Bengaluru", 12.9716, 77.5946),
    Location("geneva", "Geneva", 46.2044, 6.1432),
    Location("nairobi", "Nairobi", -1.2921, 36.8219),
)


class ForecastProvider(Protocol):
    @property
    def locations(self) -> tuple[Location, ...]: ...

    async def get(self, slug: str) -> dict[str, Any]: ...


class OpenMeteoProvider:
    """Fetch current weather from Open-Meteo without scraping a Web UI."""

    endpoint = "https://api.open-meteo.com/v1/forecast"

    def __init__(
        self,
        *,
        locations: tuple[Location, ...] = DEFAULT_LOCATIONS,
        cache_seconds: int = 300,
        timeout_seconds: float = 8.0,
        max_response_bytes: int = 1024 * 1024,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if cache_seconds < 30:
            raise ValueError("cache_seconds must be at least 30")
        self._locations = locations
        self._by_slug = {location.slug: location for location in locations}
        if len(self._by_slug) != len(locations):
            raise ValueError("forecast location slugs must be unique")
        self._cache_seconds = cache_seconds
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._transport = transport
        self._cache: dict[str, tuple[datetime, dict[str, Any]]] = {}
        self._lock = asyncio.Lock()

    @property
    def locations(self) -> tuple[Location, ...]:
        return self._locations

    async def get(self, slug: str) -> dict[str, Any]:
        normalized = slug.strip().lower()
        location = self._by_slug.get(normalized)
        if location is None:
            raise KeyError(f"unknown forecast location '{slug}'")
        now = datetime.now(timezone.utc)
        cached = self._cache.get(normalized)
        if cached and cached[0] > now:
            return deepcopy(cached[1])
        async with self._lock:
            cached = self._cache.get(normalized)
            if cached and cached[0] > datetime.now(timezone.utc):
                return deepcopy(cached[1])
            record = await self._fetch(location)
            expiry = datetime.now(timezone.utc) + timedelta(
                seconds=self._cache_seconds
            )
            self._cache[normalized] = (expiry, record)
            return deepcopy(record)

    async def _fetch(self, location: Location) -> dict[str, Any]:
        query = {
            "latitude": f"{location.latitude:.4f}",
            "longitude": f"{location.longitude:.4f}",
            "current": "temperature_2m,precipitation,weather_code",
            "timezone": "auto",
        }
        source_url = f"{self.endpoint}?{urlencode(query)}"
        async with httpx.AsyncClient(
            timeout=self._timeout_seconds,
            follow_redirects=False,
            transport=self._transport,
        ) as client:
            async with client.stream(
                "GET",
                source_url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "AgentWeb-Forecast/0.2",
                },
            ) as response:
                response.raise_for_status()
                content_length = response.headers.get("content-length")
                if (
                    content_length
                    and int(content_length) > self._max_response_bytes
                ):
                    raise ValueError(
                        "Open-Meteo response exceeds configured size limit"
                    )
                media_type = response.headers.get("content-type", "").lower()
                if "application/json" not in media_type:
                    raise ValueError("Open-Meteo returned a non-JSON response")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self._max_response_bytes:
                        raise ValueError(
                            "Open-Meteo response exceeds configured size limit"
                        )
        payload = json.loads(body)
        current = payload.get("current")
        if not isinstance(current, Mapping):
            raise ValueError("Open-Meteo response has no current weather object")
        try:
            temperature = float(current["temperature_2m"])
            precipitation = float(current["precipitation"])
            weather_code = int(current["weather_code"])
            observed_at = str(current["time"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Open-Meteo current weather is malformed") from exc
        retrieved = datetime.now(timezone.utc)
        expires = retrieved + timedelta(seconds=self._cache_seconds)
        return {
            "slug": location.slug,
            "location": location.name,
            "coordinates": {
                "latitude": location.latitude,
                "longitude": location.longitude,
            },
            "temperatureC": temperature,
            "precipitationMm": precipitation,
            "weatherCode": weather_code,
            "condition": _weather_condition(weather_code),
            "observedAt": observed_at,
            "retrievedAt": _timestamp(retrieved),
            "validThrough": _timestamp(expires),
            "source": source_url,
            "sourceProvider": "Open-Meteo",
        }


class StaticForecastProvider:
    """Explicit test double; never selected by production configuration."""

    def __init__(
        self,
        records: Mapping[str, Mapping[str, Any]],
    ) -> None:
        self._records = {
            slug: deepcopy(dict(record)) for slug, record in records.items()
        }
        self._locations = tuple(
            Location(
                slug=slug,
                name=str(record["location"]),
                latitude=float(record.get("latitude", 0)),
                longitude=float(record.get("longitude", 0)),
            )
            for slug, record in self._records.items()
        )

    @property
    def locations(self) -> tuple[Location, ...]:
        return self._locations

    async def get(self, slug: str) -> dict[str, Any]:
        try:
            return deepcopy(self._records[slug.strip().lower()])
        except KeyError as exc:
            raise KeyError(f"unknown forecast location '{slug}'") from exc


def _weather_condition(code: int) -> str:
    if code == 0:
        return "Clear sky"
    if code in {1, 2, 3}:
        return "Partly cloudy"
    if code in {45, 48}:
        return "Fog"
    if code in {51, 53, 55, 56, 57}:
        return "Drizzle"
    if code in {61, 63, 65, 66, 67, 80, 81, 82}:
        return "Rain"
    if code in {71, 73, 75, 77, 85, 86}:
        return "Snow"
    if code in {95, 96, 99}:
        return "Thunderstorm"
    return "Unknown"


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
