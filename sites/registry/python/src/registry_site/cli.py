"""Operator commands for serving and populating the Agent Web registry."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit

from agent_web_server import (
    PublisherIdentity,
    active_identity_paths,
    load_runtime_identity,
    read_secret_file,
)
import uvicorn

from .app import create_app
from .indexer import RegistryIndexer
from .store import RegistryStore


def _identity(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
) -> tuple[PublisherIdentity, Path, Path]:
    if args.identity_directory:
        if args.did_document or args.private_key:
            parser.error(
                "--identity-directory cannot be combined with direct identity files"
            )
        did_path, key_path = active_identity_paths(args.identity_directory)
    else:
        if not args.did_document or not args.private_key:
            parser.error(
                "provide --identity-directory or both identity file arguments"
            )
        did_path = Path(args.did_document)
        key_path = Path(args.private_key)
    return PublisherIdentity.from_files(did_path, key_path), did_path, key_path


def _identity_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--identity-directory")
    parser.add_argument("--did-document")
    parser.add_argument("--private-key")


def serve() -> None:
    parser = argparse.ArgumentParser(description="Run the Agent Web Registry")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8643)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--database", default=".agent-web/registry.db")
    parser.add_argument("--nonce-database", default=".agent-web/registry-nonces.db")
    parser.add_argument("--handle-database", default=".agent-web/registry-wns.db")
    parser.add_argument("--tls-certificate", required=True)
    parser.add_argument("--tls-private-key", required=True)
    parser.add_argument("--metrics-token-file")
    parser.add_argument("--operator-token-file")
    parser.add_argument("--vault-url")
    parser.add_argument("--vault-mount", default="transit")
    parser.add_argument("--vault-key")
    parser.add_argument("--vault-token-file")
    parser.add_argument("--vault-namespace")
    parser.add_argument("--vault-ca-file")
    parser.add_argument("--access-token-private-key")
    _identity_args(parser)
    args = parser.parse_args()
    parsed = urlsplit(args.base_url)
    if parsed.scheme != "https":
        parser.error("--base-url must use https")
    if parsed.port not in {None, args.port}:
        parser.error("--base-url port must match --port")
    try:
        identity = load_runtime_identity(
            identity_directory=args.identity_directory,
            did_document=args.did_document,
            private_key=args.private_key,
            vault_url=args.vault_url,
            vault_mount=args.vault_mount,
            vault_key=args.vault_key,
            vault_token_file=args.vault_token_file,
            vault_namespace=args.vault_namespace,
            vault_ca_file=args.vault_ca_file,
            access_token_private_key=args.access_token_private_key,
        )
    except (OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    for value in (args.database, args.nonce_database, args.handle_database):
        Path(value).parent.mkdir(parents=True, exist_ok=True)
    uvicorn.run(
        create_app(
            database=args.database,
            nonce_database=args.nonce_database,
            handle_database=args.handle_database,
            base_url=args.base_url,
            identity=identity,
            metrics_token=(
                read_secret_file(args.metrics_token_file)
                if args.metrics_token_file else None
            ),
            operator_token=(
                read_secret_file(args.operator_token_file)
                if args.operator_token_file else None
            ),
        ),
        host=args.host,
        port=args.port,
        ssl_certfile=args.tls_certificate,
        ssl_keyfile=args.tls_private_key,
    )


def index() -> None:
    parser = argparse.ArgumentParser(
        description="Proof-verify and atomically index one Agent Web publisher"
    )
    parser.add_argument("--database", required=True)
    parser.add_argument("--agent-description-url", required=True)
    parser.add_argument("--max-resources", type=int, default=100)
    parser.add_argument("--max-total-bytes", type=int, default=32 * 1024 * 1024)
    parser.add_argument("--allow-private-network", action="store_true")
    _identity_args(parser)
    args = parser.parse_args()
    _, did_path, key_path = _identity(parser, args)
    database = Path(args.database)
    database.parent.mkdir(parents=True, exist_ok=True)
    store = RegistryStore(database)
    try:
        result = RegistryIndexer(
            store,
            did_document_path=did_path,
            private_key_path=key_path,
            allow_private_networks=args.allow_private_network,
            max_total_bytes=args.max_total_bytes,
        ).index(
            args.agent_description_url,
            max_resources=args.max_resources,
        )
        print(json.dumps(result, indent=2))
    finally:
        store.close()
