"""Run Moltbook as an independently packaged Agent Web site."""

from __future__ import annotations

from agent_web_server import RunningSite, start_site
from agent_web_server import PublisherIdentity

from .app import create_app


def start_moltbook(
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    database: str = ":memory:",
    seed: bool = True,
    forecast_entrypoint: str | None = None,
    identity: PublisherIdentity,
    tls_certificate: str,
    tls_private_key: str,
    nonce_database: str = ":memory:",
    authorization_database: str = ":memory:",
) -> RunningSite:
    return start_site(
        lambda base_url: create_app(
            database=database,
            base_url=base_url,
            seed=seed,
            forecast_entrypoint=forecast_entrypoint,
            identity=identity,
            nonce_database=nonce_database,
            authorization_database=authorization_database,
        ),
        host=host,
        port=port,
        tls_certificate=tls_certificate,
        tls_private_key=tls_private_key,
    )


start_agent_web = start_moltbook
