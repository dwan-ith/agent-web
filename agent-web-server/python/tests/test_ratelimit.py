from __future__ import annotations

import unittest

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from agent_web_server.ratelimit import (
    RateLimitRule,
    SlidingWindowCounter,
    caller_did_key,
    client_ip_key,
    install_rate_limit,
    proxied_client_key,
)


def _client(
    rules: list[RateLimitRule],
    *,
    limiter: SlidingWindowCounter | None = None,
) -> TestClient:
    app = FastAPI()

    @app.get("/ping")
    async def ping() -> JSONResponse:
        return JSONResponse({"pong": True})

    @app.get("/did-echo")
    async def did_echo(request: Request) -> JSONResponse:
        request.state.did = request.headers.get("x-test-did")
        return JSONResponse({"ok": True})

    install_rate_limit(app, rules, limiter=limiter)
    return TestClient(app)


class SlidingWindowCounterTests(unittest.TestCase):
    def test_allows_up_to_limit_then_blocks_until_window_slides(self) -> None:
        counter = SlidingWindowCounter()
        now = 1_000.0
        for index in range(3):
            allowed, retry = counter.hit(
                rule="r",
                key="k",
                max_requests=3,
                window_seconds=10,
                now=now + index,
            )
            self.assertTrue(allowed, f"event {index} must pass")
            self.assertEqual(retry, 0.0)
        blocked, retry = counter.hit(
            rule="r", key="k", max_requests=3, window_seconds=10, now=now + 4
        )
        self.assertFalse(blocked)
        self.assertGreater(retry, 0.0)
        # The first event expires at 1010; by then the window has slid open.
        allowed, _ = counter.hit(
            rule="r", key="k", max_requests=3, window_seconds=10, now=now + 11
        )
        self.assertTrue(allowed)

    def test_keys_and_rules_are_isolated(self) -> None:
        counter = SlidingWindowCounter()
        counter.hit(rule="r", key="a", max_requests=1, window_seconds=5)
        allowed, _ = counter.hit(rule="r", key="b", max_requests=1, window_seconds=5)
        self.assertTrue(allowed)
        allowed_other_rule, _ = counter.hit(
            rule="other", key="a", max_requests=1, window_seconds=5
        )
        self.assertTrue(allowed_other_rule)
        replayed, _ = counter.hit(rule="r", key="a", max_requests=1, window_seconds=5)
        self.assertFalse(replayed)
        self.assertEqual(counter.tracked_keys(), 3)

    def test_distinct_key_pressure_sheds_new_keys_not_tracked_ones(self) -> None:
        counter = SlidingWindowCounter(max_tracked_keys=2)
        counter.hit(rule="r", key="a", max_requests=1, window_seconds=100, now=1)
        counter.hit(rule="r", key="b", max_requests=1, window_seconds=100, now=1)
        allowed_c, retry = counter.hit(
            rule="r", key="c", max_requests=1, window_seconds=100, now=2
        )
        self.assertFalse(allowed_c)
        self.assertEqual(retry, 100.0)
        # Tracked live keys are never evicted to make room for new ones.
        still_allowed, _ = counter.hit(
            rule="r", key="b", max_requests=2, window_seconds=100, now=2
        )
        self.assertTrue(still_allowed)

    def test_invalid_construction_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            SlidingWindowCounter(max_tracked_keys=0)


class RateLimitRuleTests(unittest.TestCase):
    def test_rule_validation(self) -> None:
        with self.assertRaises(ValueError):
            RateLimitRule(name="", max_requests=1, window_seconds=1)
        with self.assertRaises(ValueError):
            RateLimitRule(name="x", max_requests=True, window_seconds=1)
        with self.assertRaises(ValueError):
            RateLimitRule(name="x", max_requests=0, window_seconds=1)
        with self.assertRaises(ValueError):
            RateLimitRule(name="x", max_requests=1, window_seconds=0)
        with self.assertRaises(ValueError):
            RateLimitRule(name="x", max_requests=1, window_seconds=3601)

    def test_install_rejects_empty_or_duplicate_rules(self) -> None:
        app = FastAPI()
        with self.assertRaises(ValueError):
            install_rate_limit(app, [])
        duplicate = RateLimitRule(name="same", max_requests=1, window_seconds=1)
        with self.assertRaises(ValueError):
            install_rate_limit(app, [duplicate, duplicate])


class MiddlewareTests(unittest.TestCase):
    def test_blocks_over_limit_with_retry_after_and_passes_below(self) -> None:
        client = _client([RateLimitRule(name="ping", max_requests=2, window_seconds=60)])
        self.assertEqual(client.get("/ping").status_code, 200)
        self.assertEqual(client.get("/ping").status_code, 200)
        limited = client.get("/ping")
        self.assertEqual(limited.status_code, 429)
        self.assertIn("Retry-After", limited.headers)
        self.assertIn("rate limit exceeded", limited.json()["detail"])

    def test_matches_selects_only_matching_routes(self) -> None:
        client = _client(
            [
                RateLimitRule(
                    name="only-ping",
                    max_requests=1,
                    window_seconds=60,
                    matches=lambda request: request.url.path == "/ping",
                )
            ]
        )
        self.assertEqual(client.get("/ping").status_code, 200)
        self.assertEqual(client.get("/ping").status_code, 429)
        other = client.get("/did-echo")
        self.assertEqual(other.status_code, 200)

    def test_caller_did_key_separates_identities_and_falls_back_to_ip(self) -> None:
        app = FastAPI()

        @app.get("/did-echo")
        async def did_echo(request: Request) -> JSONResponse:
            return JSONResponse({"ok": True})

        install_rate_limit(
            app,
            [
                RateLimitRule(
                    name="did",
                    max_requests=1,
                    window_seconds=60,
                    key=caller_did_key,
                )
            ],
        )

        # Added after the limiter, so this authentication middleware runs
        # BEFORE limiting: the same ordering contract deployments follow by
        # installing rate limits before install_security.
        @app.middleware("http")
        async def fake_authentication(request: Request, call_next):
            request.state.did = request.headers.get("x-test-did")
            return await call_next(request)

        client = TestClient(app)
        first = client.get("/did-echo", headers={"x-test-did": "did:wba:a"})
        second = client.get("/did-echo", headers={"x-test-did": "did:wba:b"})
        third = client.get("/did-echo", headers={"x-test-did": "did:wba:a"})
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(third.status_code, 429)

    def test_none_key_skips_the_request(self) -> None:
        client = _client(
            [
                RateLimitRule(
                    name="never",
                    max_requests=1,
                    window_seconds=60,
                    key=lambda _request: None,
                )
            ]
        )
        for _ in range(3):
            self.assertEqual(client.get("/ping").status_code, 200)

    def test_proxied_client_key_trusts_only_the_configured_chain(self) -> None:
        class FakeRequest:
            def __init__(self, forwarded: str | None) -> None:
                self.client = None
                self.headers = (
                    {"x-forwarded-for": forwarded} if forwarded else {}
                )

        key = proxied_client_key(trusted_proxy_count=1)
        # One trusted proxy: the caller is the address that proxy appended,
        # i.e. the rightmost value.
        self.assertEqual(
            key(FakeRequest("203.0.113.9, 198.51.100.7")),
            "proxy:198.51.100.7",
        )
        # Anything further left is attacker-supplied and ignored.
        self.assertEqual(
            key(FakeRequest("10.0.0.1, 203.0.113.9, 198.51.100.7")),
            "proxy:198.51.100.7",
        )
        # A single entry is what one trusted proxy appends for a client
        # that sent no header of its own.
        self.assertEqual(
            key(FakeRequest("198.51.100.7")),
            "proxy:198.51.100.7",
        )
        self.assertIsNone(key(FakeRequest(None)))
        with self.assertRaises(ValueError):
            proxied_client_key(trusted_proxy_count=-1)


if __name__ == "__main__":
    unittest.main()
