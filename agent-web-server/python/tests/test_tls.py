from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from agent_web_server import generate_local_tls
from agent_web_server import tls as tls_module


class LocalTLSMaterialTests(unittest.TestCase):
    def test_private_key_uses_exclusive_secret_writer(self) -> None:
        with TemporaryDirectory() as temporary, patch(
            "agent_web_server.tls._exclusive_write",
            wraps=tls_module._exclusive_write,
        ) as writer:
            material = generate_local_tls(Path(temporary) / "tls")

        modes = {Path(call.args[0]).name: call.args[2] for call in writer.call_args_list}
        self.assertEqual(modes[material.private_key.name], 0o600)
        self.assertEqual(modes[material.certificate.name], 0o644)
        self.assertEqual(modes[material.ca_certificate.name], 0o644)

    def test_partial_tls_material_is_removed_if_a_write_fails(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary) / "tls"
            real_writer = tls_module._exclusive_write
            writes = 0

            def fail_second(path: Path, content: bytes, mode: int) -> None:
                nonlocal writes
                writes += 1
                if writes == 2:
                    raise OSError("simulated write failure")
                real_writer(path, content, mode)

            with patch("agent_web_server.tls._exclusive_write", fail_second):
                with self.assertRaisesRegex(OSError, "simulated"):
                    generate_local_tls(root)
            self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
