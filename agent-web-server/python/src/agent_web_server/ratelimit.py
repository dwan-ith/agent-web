"""Bounded, abuse-resistant request rate limiting for Agent Web publishers.

The limiter implements a deterministic sliding-window counter per key. It is
denial-of-service surface reduction, not authorization: a 429 never implies
the caller was authenticated, and passing the limiter grants no authority.

Keys are operator-supplied functions of the request so deployments can choose
authenticated-DID keys where available and client-IP keys elsewhere. Client
IPs reflect the direct TLS peer unless the operator runs behind a trusted
proxy that reconstructs ``X-Forwarded-For``; publishers behind proxies MUST
supply their own key function rather than trusting forwarding headers.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import logging
from threading import Lock
import time
from typing import Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


MAX_TRACKED_KEYS = 10_000

LOGGER = logging.getLogger("agent_web.security")

KeyFunction = Callable[[Request], "str | None"]


def client_ip_key(request: Request) -> str | None:
    """Direct TLS peer address; unsafe behind untrusted proxies."""

    host = getattr(request.client, "host", None) if request.client else None
    return str(host) if host else None


def proxied_client_key(trusted_proxy_count: int = 1) -> KeyFunction:
    """Client IP reconstructed from ``X-Forwarded-For`` through trusted proxies.

    Operators MUST configure ``trusted_proxy_count`` to the exact number of
    proxy hops they control that append to ``X-Forwarded-For``, and MUST
    ensure the origin accepts connections only from that proxy tier (the
    default-deny network policy does this). Each trusted proxy appends the
    address it saw, so with N trusted proxies the caller is the Nth value
    from the right; anything further left is attacker-controlled. Headers
    carrying fewer than N addresses fall back to the direct peer.
    """

    if trusted_proxy_count < 0 or trusted_proxy_count > 8:
        raise ValueError("trusted_proxy_count must be between 0 and 8")

    def key(request: Request) -> str | None:
        direct = client_ip_key(request)
        forwarded = request.headers.get("x-forwarded-for")
        if not forwarded:
            return direct
        hops = [hop.strip() for hop in forwarded.split(",") if hop.strip()]
        if trusted_proxy_count == 0 or len(hops) < trusted_proxy_count:
            # Fewer hops than the configured proxy chain: the leftmost
            # values are attacker-supplied, so trust only the direct peer.
            return direct
        return f"proxy:{hops[-trusted_proxy_count]}"

    return key


def caller_did_key(request: Request) -> str | None:
    """Authenticated DID when present, otherwise the direct peer address."""

    did = getattr(request.state, "did", None)
    if isinstance(did, str) and did:
        return f"did:{did}"
    return client_ip_key(request)


@dataclass(frozen=True, slots=True)
class RateLimitRule:
    """Apply one sliding window to requests selected by ``matches``."""

    name: str
    max_requests: int
    window_seconds: float
    key: KeyFunction = client_ip_key
    matches: Callable[[Request], bool] = lambda _request: True

    def __post_init__(self) -> None:
        if not self.name or len(self.name) > 100:
            raise ValueError("rate limit rule requires a bounded name")
        if isinstance(self.max_requests, bool) or self.max_requests < 1:
            raise ValueError("max_requests must be a positive integer")
        if self.window_seconds <= 0 or self.window_seconds > 3600:
            raise ValueError("window_seconds must be in (0, 3600]")


class SlidingWindowCounter:
    """One bounded map of sliding windows shared by one process."""

    def __init__(self, *, max_tracked_keys: int = MAX_TRACKED_KEYS) -> None:
        if max_tracked_keys < 1:
            raise ValueError("max_tracked_keys must be a positive integer")
        self._lock = Lock()
        self._windows: "OrderedDict[tuple[str, str], list[float]]" = OrderedDict()
        self._max_keys = max_tracked_keys

    def hit(
        self,
        *,
        rule: str,
        key: str,
        max_requests: int,
        window_seconds: float,
        now: float | None = None,
    ) -> tuple[bool, float]:
        """Record one event; return ``(allowed, retry_after_seconds)``."""

        current = time.monotonic() if now is None else now
        cutoff = current - window_seconds
        bucket_key = (rule, key)
        with self._lock:
            bucket = self._windows.get(bucket_key)
            if bucket is not None:
                while bucket and bucket[0] <= cutoff:
                    bucket.pop(0)
                if not bucket:
                    del self._windows[bucket_key]
                    bucket = None
            if bucket is None:
                if len(self._windows) >= self._max_keys:
                    self._drop_expired_buckets_locked(cutoff)
                if len(self._windows) >= self._max_keys:
                    # Sustained pressure from distinct live keys: shed this
                    # new key's load rather than evict tracked callers.
                    return False, float(window_seconds)
                bucket = []
                self._windows[bucket_key] = bucket
            if len(bucket) < max_requests:
                bucket.append(current)
                self._windows.move_to_end(bucket_key)
                return True, 0.0
            retry_after = max(bucket[0] + window_seconds - current, 0.001)
            return False, retry_after

    def tracked_keys(self) -> int:
        with self._lock:
            return len(self._windows)

    def _drop_expired_buckets_locked(self, cutoff: float) -> None:
        for bucket_key in [
            key for key, bucket in self._windows.items() if not bucket
        ]:
            del self._windows[bucket_key]


def install_rate_limit(
    app: FastAPI,
    rules: list[RateLimitRule],
    *,
    limiter: SlidingWindowCounter | None = None,
) -> SlidingWindowCounter:
    """Reject requests exceeding any operator-declared sliding window."""

    if not rules:
        raise ValueError("at least one rate limit rule is required")
    names: set[str] = set()
    for rule in rules:
        if rule.name in names:
            raise ValueError(f"duplicate rate limit rule name: {rule.name}")
        names.add(rule.name)
    limiter = limiter or SlidingWindowCounter()

    @app.middleware("http")
    async def enforce_rate_limits(
        request: Request,
        call_next: Callable[[Request], Awaitable],
    ):
        for rule in rules:
            try:
                if not rule.matches(request):
                    continue
                key = rule.key(request)
            except Exception:
                LOGGER.exception(
                    "rate limit rule '%s' failed to evaluate; skipping it",
                    rule.name,
                )
                continue
            if key is None:
                continue
            allowed, retry_after = limiter.hit(
                rule=rule.name,
                key=key,
                max_requests=rule.max_requests,
                window_seconds=rule.window_seconds,
            )
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": (
                            f"rate limit exceeded for '{rule.name}'"
                        )
                    },
                    headers={"Retry-After": f"{max(retry_after, 1):.0f}"},
                )
        return await call_next(request)

    app.state.rate_limiter = limiter
    return limiter
