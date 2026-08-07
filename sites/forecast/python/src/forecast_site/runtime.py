from __future__ import annotations

from agent_web_server import PublisherIdentity, RunningSite, start_site

from .app import create_app
from .provider import ForecastProvider


def start_forecast(
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    moltbook_entrypoint: str | None = None,
    identity: PublisherIdentity,
    tls_certificate: str,
    tls_private_key: str,
    provider: ForecastProvider | None = None,
    nonce_database: str = ":memory:",
) -> RunningSite:
    return start_site(
        lambda base_url: create_app(
            base_url=base_url,
            moltbook_entrypoint=moltbook_entrypoint,
            identity=identity,
            provider=provider,
            nonce_database=nonce_database,
        ),
        host=host,
        port=port,
        tls_certificate=tls_certificate,
        tls_private_key=tls_private_key,
    )
