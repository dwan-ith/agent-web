from __future__ import annotations

from pathlib import Path
import os
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from agent_web_browser import create_app
from agent_web_server import generate_publisher_identity, write_identity
from fastapi.testclient import TestClient


class BrowserDaemonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.identity = generate_publisher_identity(
            base_url="https://localhost:7443",
            agent_name="browser",
            agent_description_path="/browser/ad.json",
        )
        self.did_path, self.key_path = write_identity(
            self.identity,
            directory=Path(self.temp.name) / "identity",
        )
        self.app = create_app(
            identity=self.identity,
            did_document_path=self.did_path,
            private_key_path=self.key_path,
            base_url="https://localhost:7443",
            static_directory=(
                Path(__file__).resolve().parents[1]
                / "src"
                / "agent_web_browser"
                / "static"
            ),
            allow_private_networks=True,
            session_token="test-session-token",
        )
        self.client = TestClient(
            self.app,
            base_url="https://localhost:7443",
        )
        self.token_headers = {"X-Agent-Web-Browser-Token": "test-session-token"}

    def tearDown(self) -> None:
        self.client.close()
        self.temp.cleanup()

    def test_serves_real_ui_and_reports_browser_identity(self) -> None:
        page = self.client.get("/", params={"token": "test-session-token"})
        self.assertEqual(page.status_code, 200)
        self.assertIn("Agent Web Browser", page.text)
        self.assertIn('name="agent-web-daemon-token"', page.text)
        status = self.client.get("/api/status", headers=self.token_headers).json()
        self.assertEqual(status["callerDid"], self.identity.did)
        self.assertEqual(status["allowedOrigins"], [])

    def test_api_and_ui_require_the_session_token(self) -> None:
        self.assertEqual(self.client.get("/api/status").status_code, 401)
        self.assertEqual(self.client.get("/").status_code, 401)
        wrong = {"X-Agent-Web-Browser-Token": "not-the-token"}
        self.assertEqual(
            self.client.get("/api/status", headers=wrong).status_code,
            401,
        )
        # The tokenized UI entry injects the token the React client sends.
        query_entry = self.client.get("/", params={"token": "test-session-token"})
        self.assertEqual(query_entry.status_code, 200)
        header_entry = self.client.get("/", headers=self.token_headers)
        self.assertEqual(header_entry.status_code, 200)

    def test_cross_origin_mutation_and_non_https_discovery_are_blocked(self) -> None:
        cross_origin = self.client.post(
            "/api/connect",
            headers={**self.token_headers, "Origin": "https://evil.test"},
            json={"agentDescriptionUrl": "https://agent.test/ad.json"},
        )
        self.assertEqual(cross_origin.status_code, 403)
        invalid = self.client.post(
            "/api/connect",
            headers=self.token_headers,
            json={"agentDescriptionUrl": "http://agent.test/ad.json"},
        )
        self.assertEqual(invalid.status_code, 400)

    def test_origin_policy_rejects_paths_and_accepts_https_origin(self) -> None:
        disconnected = self.client.post(
            "/api/origins",
            headers=self.token_headers,
            json={"origin": "https://agent.test"},
        )
        self.assertEqual(disconnected.status_code, 400)

    def test_connect_accepts_a_verified_wns_handle(self) -> None:
        candidate = SimpleNamespace(
            agent_description_url="https://publisher.example/moltbook/ad.json",
            handle_binding=SimpleNamespace(
                handle="moltbook.publisher.example",
                binding_generation="9",
            ),
            allowed_origins={"https://publisher.example"},
            discover_async=AsyncMock(
                return_value={
                    "name": "Moltbook",
                    "description": "Agent-native discussions",
                }
            ),
            open_entrypoint_async=AsyncMock(
                return_value={"@id": "https://publisher.example/resources/index.json"}
            ),
        )
        with patch(
            "agent_web_browser.daemon.BrowserDaemon._anp_browser",
            return_value=SimpleNamespace(
                from_handle_async=AsyncMock(return_value=candidate)
            ),
        ) as resolver:
            result = __import__("asyncio").run(
                self.app.state.browser_daemon.connect(
                    "moltbook.publisher.example"
                )
            )
        resolver.assert_called_once()
        connected = result["status"]["connectedAgent"]
        self.assertEqual(connected["url"], candidate.agent_description_url)
        self.assertEqual(connected["handle"], "moltbook.publisher.example")
        self.assertEqual(connected["bindingGeneration"], "9")

    def test_connect_prefers_web_native_discovery(self) -> None:
        candidate = SimpleNamespace(
            allowed_origins={"https://publisher.example"},
            discover=AsyncMock(
                return_value={
                    "publisher": "https://publisher.example/.well-known/agent-web",
                    "agentWeb": {
                        "entryPoint": "https://publisher.example/resources/index"
                    },
                }
            ),
            open_entrypoint=AsyncMock(
                return_value={
                    "@id": "https://publisher.example/resources/index",
                    "name": "Web publisher",
                    "description": "No ANP discovery required",
                }
            ),
        )
        with patch(
            "agent_web_browser.daemon.WebAgentBrowser",
            return_value=candidate,
        ) as constructor:
            result = __import__("asyncio").run(
                self.app.state.browser_daemon.connect(
                    "https://publisher.example/.well-known/agent-web"
                )
            )
        constructor.assert_called_once()
        candidate.open_entrypoint.assert_awaited_once()
        self.assertEqual(
            result["status"]["connectedAgent"]["binding"],
            "Agent Web HTTP",
        )

    def test_web_native_action_uses_http_invocation(self) -> None:
        candidate = SimpleNamespace(
            allowed_origins={"https://publisher.example"},
            invoke=AsyncMock(return_value={"@id": "https://publisher.example/search?q=web"}),
        )
        daemon = self.app.state.browser_daemon
        daemon.browser = candidate
        daemon.browser_binding = "Agent Web HTTP"
        result = __import__("asyncio").run(
            daemon.call(
                "search",
                {"q": "web"},
                confirmed=False,
                resource_url="https://publisher.example/resources/index",
            )
        )
        self.assertEqual(result["resource"]["@id"], "https://publisher.example/search?q=web")

    def test_web_native_browser_imports_when_anp_is_unavailable(self) -> None:
        source = Path(__file__).resolve().parents[1] / "src"
        script = """
import importlib.abc
import sys
class BlockCompatibility(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'anp' or fullname.startswith('anp.') or fullname == 'agent_web_server' or fullname.startswith('agent_web_server.'):
            raise ModuleNotFoundError('compatibility dependency deliberately unavailable')
        return None
sys.meta_path.insert(0, BlockCompatibility())
from agent_web_browser import create_app
app = create_app(base_url='https://localhost:7443')
assert app.state.browser_daemon.identity is None
assert not any(name == 'anp' or name.startswith('anp.') for name in sys.modules)
"""
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(source) + os.pathsep + environment.get(
            "PYTHONPATH", ""
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
