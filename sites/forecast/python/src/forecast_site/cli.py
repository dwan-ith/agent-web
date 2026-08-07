from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit

from agent_web_server import load_runtime_identity, read_secret_file
import uvicorn

from .app import create_app
from .provider import StaticForecastProvider


def main() -> None:
    parser = argparse.ArgumentParser(description="Run secure Forecast on Agent Web")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8543)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--nonce-database", default=".agent-web/forecast-nonces.db")
    parser.add_argument("--handle-database", default=".agent-web/forecast-wns.db")
    parser.add_argument("--identity-directory")
    parser.add_argument("--did-document")
    parser.add_argument("--private-key")
    parser.add_argument("--vault-url")
    parser.add_argument("--vault-mount", default="transit")
    parser.add_argument("--vault-key")
    parser.add_argument("--vault-token-file")
    parser.add_argument("--vault-namespace")
    parser.add_argument("--vault-ca-file")
    parser.add_argument("--access-token-private-key")
    parser.add_argument("--tls-certificate", required=True)
    parser.add_argument("--tls-private-key", required=True)
    parser.add_argument("--moltbook-entrypoint")
    parser.add_argument("--metrics-token-file")
    parser.add_argument("--operator-token-file")
    parser.add_argument(
        "--static-data",
        help="explicit deterministic provider JSON for test/acceptance deployments",
    )
    args = parser.parse_args()
    parsed = urlsplit(args.base_url)
    if parsed.scheme != "https":
        parser.error("--base-url must use https")
    if parsed.port not in {None, args.port}:
        parser.error("--base-url port must match --port")
    for value in (args.nonce_database, args.handle_database):
        Path(value).parent.mkdir(parents=True, exist_ok=True)
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
    provider = None
    if args.static_data:
        static_path = Path(args.static_data)
        if static_path.stat().st_size > 1024 * 1024:
            parser.error("--static-data exceeds 1 MiB")
        records = json.loads(static_path.read_text(encoding="utf-8"))
        if not isinstance(records, dict) or not records:
            parser.error("--static-data must contain a non-empty JSON object")
        provider = StaticForecastProvider(records)
    uvicorn.run(
        create_app(
            base_url=args.base_url,
            identity=identity,
            nonce_database=args.nonce_database,
            handle_database=args.handle_database,
            moltbook_entrypoint=args.moltbook_entrypoint,
            provider=provider,
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


if __name__ == "__main__":
    main()
