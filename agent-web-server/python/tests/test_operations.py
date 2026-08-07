from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from agent_web_server import (
    AuthorizationStore,
    HandleStore,
    create_backup_bundle,
    create_coordinated_backup_bundle,
    restore_backup_bundle,
    verify_backup_bundle,
)
from moltbook_site.store import MoltbookStore


class RecoveryOperationsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.data = self.root / "live"
        self.data.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_online_backup_and_restore_preserve_canonical_security_state(self) -> None:
        moltbook_path = self.data / "moltbook.sqlite3"
        authorization_path = self.data / "authorization.sqlite3"
        wns_path = self.data / "wns.sqlite3"
        moltbook = MoltbookStore(moltbook_path, seed=False)
        authorization = AuthorizationStore(authorization_path)
        wns = HandleStore(wns_path, provider_domain="publisher.example")
        try:
            thread = moltbook.create_thread(
                title="Before backup",
                body="Canonical recovery evidence",
                author="did:wba:caller.example:agents:e1_test",
                rate_limit=None,
            )
            grant = authorization.grant(
                subject_did="did:wba:caller.example:agents:e1_test",
                action="moltbook:create_reply",
                resource=(
                    "https://publisher.example/moltbook/resources/threads/"
                    f"{thread['id']}.json"
                ),
            )
            binding = wns.bind(
                "moltbook.publisher.example",
                "did:wba:publisher.example:agents:moltbook:e1_test",
            )
            bundle = self.root / "backup"
            manifest = create_backup_bundle(
                {
                    "moltbook": moltbook_path,
                    "authorization": authorization_path,
                    "wns": wns_path,
                },
                bundle,
            )
            self.assertEqual(len(manifest["databases"]), 3)
            verify_backup_bundle(bundle)

            moltbook.create_thread(
                title="After backup",
                body="Must not appear after restore",
                author="did:wba:caller.example:agents:e1_test",
                rate_limit=None,
            )
            authorization.revoke(grant)
            wns.set_status(
                "moltbook.publisher.example",
                "revoked",
                expected_generation=binding.binding_generation,
            )
        finally:
            wns.close()
            authorization.close()
            moltbook.close()

        restored = restore_backup_bundle(bundle, self.root / "restored")
        recovered_moltbook = MoltbookStore(restored["moltbook"], seed=False)
        recovered_authorization = AuthorizationStore(restored["authorization"])
        recovered_wns = HandleStore(
            restored["wns"],
            provider_domain="publisher.example",
        )
        try:
            self.assertEqual(recovered_moltbook.count_threads(), 1)
            self.assertEqual(recovered_moltbook.get_thread(thread["id"])["title"], "Before backup")
            self.assertIsNone(recovered_authorization.list_grants()[0]["revoked_at"])
            self.assertEqual(
                recovered_wns.resolve("moltbook").binding_generation,
                "1",
            )
        finally:
            recovered_wns.close()
            recovered_authorization.close()
            recovered_moltbook.close()

        with self.assertRaises(FileExistsError):
            restore_backup_bundle(bundle, self.root / "restored")

    def test_tampering_and_untracked_files_are_rejected(self) -> None:
        database = self.data / "state.sqlite3"
        store = MoltbookStore(database, seed=True)
        store.close()
        bundle = self.root / "backup"
        create_backup_bundle({"state": database}, bundle)
        (bundle / "unexpected.txt").write_text("not in manifest", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "untracked"):
            verify_backup_bundle(bundle)

    def test_coordinated_backup_enters_and_always_exits_maintenance(self) -> None:
        database = self.data / "state.sqlite3"
        store = MoltbookStore(database, seed=True)
        store.close()
        responses = [
            _Response(b'{"maintenance":true}'),
            _Response(b'{"maintenance":false}'),
        ]
        with patch(
            "agent_web_server.operations.urlopen", side_effect=responses
        ) as mocked:
            result = create_coordinated_backup_bundle(
                {"state": database},
                self.root / "coordinated",
                maintenance_url="https://publisher.example",
                operator_token="o" * 32,
            )
        self.assertTrue(result["writesReleased"])
        self.assertEqual(mocked.call_count, 2)

        failed_responses = [
            _Response(b'{"maintenance":true}'),
            _Response(b'{"maintenance":false}'),
        ]
        with patch(
            "agent_web_server.operations.urlopen", side_effect=failed_responses
        ) as mocked:
            with self.assertRaises(FileExistsError):
                create_coordinated_backup_bundle(
                    {"state": database},
                    self.root / "coordinated",
                    maintenance_url="https://publisher.example",
                    operator_token="o" * 32,
                )
        self.assertEqual(mocked.call_count, 2)

    def test_coordinated_backup_drains_every_replica_before_snapshot(self) -> None:
        database = self.data / "replicated-state.sqlite3"
        store = MoltbookStore(database, seed=True)
        store.close()
        responses = [
            _Response(b'{"maintenance":true}'),
            _Response(b'{"maintenance":true}'),
            _Response(b'{"maintenance":false}'),
            _Response(b'{"maintenance":false}'),
        ]
        with patch(
            "agent_web_server.operations.urlopen", side_effect=responses
        ) as mocked:
            result = create_coordinated_backup_bundle(
                {"state": database},
                self.root / "replica-backup",
                maintenance_url=[
                    "https://replica-a.publisher.example",
                    "https://replica-b.publisher.example",
                ],
                operator_token="o" * 32,
            )
        self.assertEqual(mocked.call_count, 4)
        self.assertEqual(
            result["maintenanceOrigins"],
            [
                "https://replica-a.publisher.example",
                "https://replica-b.publisher.example",
            ],
        )

    def test_coordinated_backup_rejects_unsafe_control_urls(self) -> None:
        with self.assertRaisesRegex(ValueError, "HTTPS origin"):
            create_coordinated_backup_bundle(
                {"state": self.data / "absent.sqlite3"},
                self.root / "backup",
                maintenance_url="http://publisher.example/path",
                operator_token="o" * 32,
            )


class _Response:
    status = 200

    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, _size: int) -> bytes:
        return self.body


if __name__ == "__main__":
    unittest.main()
