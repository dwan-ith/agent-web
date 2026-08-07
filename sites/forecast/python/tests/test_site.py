from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from agent_web_server import generate_publisher_identity
from fastapi.testclient import TestClient
from forecast_site.app import create_app
from forecast_site.provider import StaticForecastProvider
from libagentweb import RESOURCE_MEDIA_TYPE, verify_resource


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


class ForecastSiteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        now = datetime.now(timezone.utc)
        self.provider = StaticForecastProvider(
            {
                "bengaluru": {
                    "slug": "bengaluru",
                    "location": "Bengaluru",
                    "temperatureC": 24.5,
                    "condition": "Rain",
                    "observedAt": _timestamp(now),
                    "retrievedAt": _timestamp(now),
                    "validThrough": _timestamp(now + timedelta(minutes=5)),
                    "source": "https://api.open-meteo.com/test-fixture",
                    "sourceProvider": "Open-Meteo",
                }
            }
        )
        self.publisher = generate_publisher_identity(
            base_url="https://testserver",
            agent_name="forecast",
            agent_description_path="/forecast/ad.json",
        )
        self.app = create_app(
            base_url="https://testserver",
            identity=self.publisher,
            provider=self.provider,
            nonce_database=Path(self.temp.name) / "nonces.db",
        )
        self.client = TestClient(self.app, base_url="https://testserver")

    def tearDown(self) -> None:
        self.client.close()
        self.app.state.close()
        self.temp.cleanup()

    def test_forecast_resource_is_signed_and_attributes_real_upstream(self) -> None:
        machine = self.client.get("/forecast/resources/bengaluru.json")
        self.assertEqual(machine.status_code, 200, machine.text)
        self.assertTrue(
            machine.headers["content-type"].startswith(RESOURCE_MEDIA_TYPE)
        )
        resource = verify_resource(
            machine.json(),
            publisher_did_document=self.publisher.did_document,
        )
        self.assertEqual(resource["data"]["temperatureC"], 24.5)
        self.assertEqual(
            resource["provenance"]["sources"],
            ["https://api.open-meteo.com/test-fixture"],
        )
        self.assertIn("expiresAt", resource["provenance"])

        human = self.client.get("/weather/bengaluru")
        self.assertIn("24.5 °C", human.text)
        self.assertIn(resource["@id"], human.headers["link"])

    def test_collection_action_is_safe_but_rpc_still_authenticates(self) -> None:
        entry = self.client.get("/forecast/resources/index.json").json()
        action = entry["affordances"]["actions"]["getForecast"]
        self.assertTrue(action["safe"])
        self.assertTrue(action["idempotent"])
        self.assertEqual(action["authorizationLevel"], "normal")
        self.assertEqual(
            self.client.post(
                "/forecast/rpc",
                json={
                    "jsonrpc": "2.0",
                    "method": "get_forecast",
                    "params": {"location": "bengaluru"},
                    "id": 1,
                },
            ).status_code,
            401,
        )


if __name__ == "__main__":
    unittest.main()
