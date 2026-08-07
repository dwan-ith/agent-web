"""Run the registry as an independently packaged Agent Web publisher."""

from __future__ import annotations

from agent_web_server import PublisherIdentity, RunningSite, start_site

from .app import create_app


def start_registry(
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    database: str = ":memory:",
    nonce_database: str = ":memory:",
    identity: PublisherIdentity,
    tls_certificate: str,
    tls_private_key: str,
) -> RunningSite:
    return start_site(
        lambda base_url: create_app(
            database=database,
            nonce_database=nonce_database,
            base_url=base_url,
            identity=identity,
        ),
        host=host,
        port=port,
        tls_certificate=tls_certificate,
        tls_private_key=tls_private_key,
    )
