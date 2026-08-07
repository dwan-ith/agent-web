from __future__ import annotations

import asyncio
import unittest

from agent_web_server import (
    MaintenanceGate,
    install_maintenance,
    install_observability,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient


TOKEN = "t" * 32


class MaintenanceGateTests(unittest.IsolatedAsyncioTestCase):
    async def test_enter_drains_existing_mutation_and_blocks_new_ones(self) -> None:
        gate = MaintenanceGate()
        self.assertTrue(await gate.begin_mutation())
        entering = asyncio.create_task(gate.enter(timeout=1))
        await asyncio.sleep(0)
        self.assertFalse(await gate.begin_mutation())
        self.assertFalse(entering.done())
        await gate.end_mutation()
        status = await entering
        self.assertTrue(status.maintenance)
        self.assertFalse(await gate.begin_mutation())
        self.assertFalse((await gate.exit()).maintenance)
        self.assertTrue(await gate.begin_mutation())
        await gate.end_mutation()


class OperationalSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        app = FastAPI()
        self.healthy = True

        @app.get("/items/{item_id}")
        async def item(item_id: str) -> dict[str, str]:
            return {"id": item_id}

        @app.post("/items")
        async def create_item() -> dict[str, bool]:
            return {"created": True}

        install_maintenance(
            app,
            operator_token=TOKEN,
            base_url="https://testserver",
        )
        install_observability(
            app,
            service_name="test-service",
            readiness_checks={"database": lambda: self.healthy},
            metrics_token=TOKEN,
        )
        self.client = TestClient(app, base_url="https://testserver")

    def tearDown(self) -> None:
        self.client.close()

    def test_readiness_reports_component_failure(self) -> None:
        ready = self.client.get("/ready")
        self.assertEqual(ready.status_code, 200)
        self.assertEqual(ready.json()["components"], {"database": True})
        self.healthy = False
        degraded = self.client.get("/ready")
        self.assertEqual(degraded.status_code, 503)
        self.assertEqual(degraded.json()["status"], "not-ready")

    def test_metrics_are_private_and_use_route_templates(self) -> None:
        self.assertEqual(self.client.get("/metrics").status_code, 401)
        self.client.get("/items/private-object-id")
        metrics = self.client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        self.assertEqual(metrics.status_code, 200)
        self.assertIn('route="/items/{item_id}"', metrics.text)
        self.assertNotIn("private-object-id", metrics.text)

    def test_operator_token_controls_maintenance_and_reads_continue(self) -> None:
        self.assertEqual(
            self.client.post("/ops/maintenance/enter").status_code,
            401,
        )
        headers = {"Authorization": f"Bearer {TOKEN}"}
        wrong_authority = self.client.post(
            "/ops/maintenance/enter",
            headers={**headers, "Host": "evil.test"},
        )
        self.assertEqual(wrong_authority.status_code, 421)
        entered = self.client.post("/ops/maintenance/enter", headers=headers)
        self.assertEqual(entered.status_code, 200)
        self.assertTrue(entered.json()["maintenance"])
        blocked = self.client.post("/items")
        self.assertEqual(blocked.status_code, 503)
        self.assertEqual(blocked.headers["retry-after"], "5")
        self.assertEqual(self.client.get("/items/one").status_code, 200)
        exited = self.client.post("/ops/maintenance/exit", headers=headers)
        self.assertEqual(exited.status_code, 200)
        self.assertEqual(self.client.post("/items").status_code, 200)


if __name__ == "__main__":
    unittest.main()
