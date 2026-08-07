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


if __name__ == "__main__":
    unittest.main()
