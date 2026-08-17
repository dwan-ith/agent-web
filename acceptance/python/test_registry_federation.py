from __future__ import annotations

import os
from pathlib import Path
import ssl
from tempfile import TemporaryDirectory
import unittest

from agent_web_server import (
    find_free_port,
    generate_local_tls,
    generate_publisher_identity,
    start_site,
)
from native_knowledge_site import create_app as create_native_app
from registry_site import RegistryFederator, RegistryIndexer, RegistryStore, start_registry


class LiveRegistryFederationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = TemporaryDirectory()
        root = Path(cls.temp.name)
        cls.tls = generate_local_tls(root / "tls")
        cls.previous_environment = {
            name: os.environ.get(name)
            for name in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NO_PROXY")
        }
        os.environ["SSL_CERT_FILE"] = str(cls.tls.ca_certificate)
        os.environ["REQUESTS_CA_BUNDLE"] = str(cls.tls.ca_certificate)
        os.environ["NO_PROXY"] = "localhost,127.0.0.1"
        import aiohttp.connector

        aiohttp.connector._SSL_CONTEXT_VERIFIED = ssl.create_default_context(
            cafile=str(cls.tls.ca_certificate)
        )
        ports: list[int] = []
        while len(ports) < 3:
            port = find_free_port()
            if port not in ports:
                ports.append(port)
        native_port, peer_port, receiver_port = ports
        cls.native_base = f"https://localhost:{native_port}"
        cls.peer_base = f"https://localhost:{peer_port}"
        cls.receiver_base = f"https://localhost:{receiver_port}"
        cls.peer_identity = generate_publisher_identity(
            base_url=cls.peer_base,
            agent_name="peer-registry",
            agent_description_path="/registry/ad.json",
        )
        cls.receiver_identity = generate_publisher_identity(
            base_url=cls.receiver_base,
            agent_name="receiver-registry",
            agent_description_path="/registry/ad.json",
        )
        cls.native = start_site(
            lambda base_url: create_native_app(
                database=root / "native.db", base_url=base_url
            ),
            port=native_port,
            tls_certificate=str(cls.tls.certificate),
            tls_private_key=str(cls.tls.private_key),
        )
        cls.peer = start_registry(
            port=peer_port,
            database=str(root / "peer.db"),
            nonce_database=str(root / "peer-nonces.db"),
            identity=cls.peer_identity,
            tls_certificate=str(cls.tls.certificate),
            tls_private_key=str(cls.tls.private_key),
        )
        cls.receiver = start_registry(
            port=receiver_port,
            database=str(root / "receiver.db"),
            nonce_database=str(root / "receiver-nonces.db"),
            identity=cls.receiver_identity,
            tls_certificate=str(cls.tls.certificate),
            tls_private_key=str(cls.tls.private_key),
        )
        cls.peer_index = RegistryIndexer(
            cls.peer.app.state.registry_store,
            allow_private_networks=True,
        ).index(f"{cls.native_base}/.well-known/agent-web")
        cls.sync_result = RegistryFederator(
            RegistryIndexer(
                cls.receiver.app.state.registry_store,
                allow_private_networks=True,
            ),
            allow_private_networks=True,
        ).sync(f"{cls.peer_base}/.well-known/agent-web")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.receiver.stop()
        cls.peer.stop()
        cls.native.stop()
        for name, value in cls.previous_environment.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        cls.temp.cleanup()

    def test_receiver_reverifies_native_source_without_transitive_trust(self) -> None:
        self.assertEqual(self.peer_index["binding"], "Agent Web")
        self.assertEqual(self.sync_result["sourcesAdvertised"], 1)
        self.assertEqual(self.sync_result["sourcesIndexed"], 1)
        self.assertEqual(self.sync_result["failures"], [])
        self.assertEqual(
            self.sync_result["trust"], "independent-source-reverification"
        )
        matches = self.receiver.app.state.registry_store.search(
            "Native Knowledge", limit=10
        )
        self.assertTrue(matches)
        self.assertEqual(
            matches[0]["source"]["publisher"],
            f"{self.native_base}/.well-known/agent-web",
        )
        self.assertEqual(
            matches[0]["source"]["discoveryUrl"],
            f"{self.native_base}/.well-known/agent-web",
        )
        self.assertNotEqual(
            matches[0]["source"]["publisher"], self.peer_identity.did
        )


if __name__ == "__main__":
    unittest.main()
