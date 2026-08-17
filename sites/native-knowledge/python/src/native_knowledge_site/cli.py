"""Serve the native knowledge site over operator-provided TLS."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import uvicorn

from .app import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run an agent-only Agent Web site")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8843)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--database", default=".agent-web/native-knowledge.db")
    parser.add_argument(
        "--replay-database", default=".agent-web/native-knowledge-replays.db"
    )
    parser.add_argument(
        "--caller-controller",
        action="append",
        default=[],
        metavar="JSON_FILE",
        help="trusted HTTPS caller controller document; may be repeated",
    )
    parser.add_argument(
        "--annotation-writer",
        action="append",
        default=[],
        metavar="HTTPS_CONTROLLER",
        help="trusted caller allowed to create annotations; may be repeated",
    )
    parser.add_argument("--signing-key", required=True)
    parser.add_argument("--tls-certificate", required=True)
    parser.add_argument("--tls-private-key", required=True)
    args = parser.parse_args()
    key = serialization.load_pem_private_key(Path(args.signing_key).read_bytes(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        parser.error("--signing-key must contain an Ed25519 private key")
    controllers = {}
    for filename in args.caller_controller:
        try:
            document = json.loads(Path(filename).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            parser.error(f"could not read caller controller {filename}: {exc}")
        identifier = document.get("id") if isinstance(document, dict) else None
        if not isinstance(identifier, str) or not identifier.startswith("https://"):
            parser.error(f"caller controller {filename} has no HTTPS id")
        if identifier in controllers:
            parser.error(f"duplicate caller controller id: {identifier}")
        controllers[identifier] = document
    Path(args.database).parent.mkdir(parents=True, exist_ok=True)
    Path(args.replay_database).parent.mkdir(parents=True, exist_ok=True)
    uvicorn.run(
        create_app(
            database=args.database,
            replay_database=args.replay_database,
            base_url=args.base_url,
            private_key=key,
            caller_controllers=controllers,
            annotation_writers=args.annotation_writer,
        ),
        host=args.host,
        port=args.port,
        ssl_certfile=args.tls_certificate,
        ssl_keyfile=args.tls_private_key,
    )


if __name__ == "__main__":
    main()
