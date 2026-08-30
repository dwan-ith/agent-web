from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import httpx

from agent_web_line import cli


class LineModeCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.did_document = str(base / "did.json")
        self.private_key = str(base / "key.pem")
        Path(self.did_document).write_text("{}", encoding="utf-8")
        Path(self.private_key).write_text("key", encoding="utf-8")
        self.common = [
            "--did-document",
            self.did_document,
            "--private-key",
            self.private_key,
        ]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _run(self, argv: list[str]) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = cli.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_open_prints_the_browsers_json_result(self) -> None:
        resource = {"@id": "https://agent.example/index", "name": "Index"}
        with mock.patch.object(
            cli, "_browser", return_value=mock.Mock(open=mock.Mock(return_value=resource))
        ) as factory:
            code, out, err = self._run(
                ["open", "https://agent.example/index", "--description",
                 "https://agent.example/ad.json", *self.common]
            )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), resource)
        self.assertEqual(err, "")
        args = factory.call_args[0][0]
        self.assertEqual(args.command, "open")

    def test_transport_timeout_is_mapped_to_a_clean_error(self) -> None:
        with mock.patch.object(
            cli,
            "_browser",
            return_value=mock.Mock(
                open=mock.Mock(
                    side_effect=httpx.ConnectTimeout("timed out")
                )
            ),
        ):
            code, out, err = self._run(
                ["open", "https://agent.example/index", "--description",
                 "https://agent.example/ad.json", *self.common]
            )
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error:", err)

    def test_missing_identity_files_are_mapped_to_a_clean_error(self) -> None:
        code, out, err = self._run(
            ["open", "https://agent.example/index", "--description",
             "https://agent.example/ad.json",
             "--did-document", str(Path(self.temp.name) / "absent.json"),
             "--private-key", self.private_key]
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error:", err)

    def test_params_must_decode_to_a_json_object(self) -> None:
        with mock.patch.object(cli, "_browser"):
            code, out, err = self._run(
                ["call", "https://agent.example/ad.json", "search",
                 "--params", "[1]", *self.common]
            )
        self.assertEqual(code, 1)
        self.assertIn("JSON object", err)


if __name__ == "__main__":
    unittest.main()
