from __future__ import annotations

import unittest

import httpx
from forecast_site.provider import Location, OpenMeteoProvider


class OpenMeteoProviderTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_adapter_parses_and_caches_bounded_json(self) -> None:
        requests = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal requests
            requests += 1
            self.assertEqual(request.url.host, "api.open-meteo.com")
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json={
                    "current": {
                        "time": "2026-07-30T12:00",
                        "temperature_2m": 21.25,
                        "precipitation": 0.4,
                        "weather_code": 61,
                    }
                },
            )

        provider = OpenMeteoProvider(
            locations=(Location("test", "Test", 1.0, 2.0),),
            transport=httpx.MockTransport(handler),
        )
        first = await provider.get("test")
        second = await provider.get("test")
        self.assertEqual(requests, 1)
        self.assertEqual(first["temperatureC"], 21.25)
        self.assertEqual(first["condition"], "Rain")
        self.assertEqual(first, second)
        self.assertTrue(first["source"].startswith("https://api.open-meteo.com/"))

    async def test_non_json_upstream_is_rejected(self) -> None:
        provider = OpenMeteoProvider(
            locations=(Location("test", "Test", 1.0, 2.0),),
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    headers={"Content-Type": "text/html"},
                    text="<html>not structured</html>",
                )
            ),
        )
        with self.assertRaisesRegex(ValueError, "non-JSON"):
            await provider.get("test")

    async def test_upstream_failure_serves_marked_stale_cache(self) -> None:
        state = {"fail": False}

        def handler(request: httpx.Request) -> httpx.Response:
            if state["fail"]:
                raise httpx.ConnectError("upstream unreachable")
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json={
                    "current": {
                        "time": "2026-07-30T12:00",
                        "temperature_2m": 21.25,
                        "precipitation": 0.4,
                        "weather_code": 61,
                    }
                },
            )

        provider = OpenMeteoProvider(
            locations=(Location("test", "Test", 1.0, 2.0),),
            cache_seconds=30,
            transport=httpx.MockTransport(handler),
        )
        fresh = await provider.get("test")
        self.assertNotIn("stale", fresh)
        provider._cache["test"] = (
            provider._cache["test"][0] - __import__("datetime").timedelta(seconds=60),
            dict(provider._cache["test"][1]),
        )
        state["fail"] = True
        stale = await provider.get("test")
        self.assertTrue(stale["stale"])
        # The original retrieval time is preserved exactly: a re-attestation
        # must not claim an upstream observation that never happened.
        self.assertEqual(stale["retrievedAt"], fresh["retrievedAt"])
        self.assertIn("reverifiedAt", stale)
        self.assertGreater(stale["reverifiedAt"], fresh["retrievedAt"])
        self.assertEqual(stale["temperatureC"], fresh["temperatureC"])
        self.assertGreater(stale["validThrough"], stale["retrievedAt"])

    async def test_upstream_failure_without_cache_raises(self) -> None:
        provider = OpenMeteoProvider(
            locations=(Location("test", "Test", 1.0, 2.0),),
            transport=httpx.MockTransport(
                lambda request: (_ for _ in ()).throw(httpx.ConnectError("down"))
            ),
        )
        with self.assertRaises(httpx.ConnectError):
            await provider.get("test")


if __name__ == "__main__":
    unittest.main()
