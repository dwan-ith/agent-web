"""Run independently implemented Agent Web ASGI sites for development."""

from __future__ import annotations

from dataclasses import dataclass
import socket
from threading import Thread
from time import monotonic, sleep
from typing import Any, Callable

import uvicorn


def find_free_port(host: str = "127.0.0.1") -> int:
    with socket.socket() as probe:
        probe.bind((host, 0))
        return int(probe.getsockname()[1])


@dataclass(slots=True)
class RunningSite:
    app: Any
    server: uvicorn.Server
    thread: Thread
    base_url: str

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)
        close = getattr(self.app.state, "close", None)
        if callable(close):
            close()
        if self.thread.is_alive():
            raise RuntimeError("Agent Web site did not stop cleanly")


def start_site(
    app_factory: Callable[[str], Any],
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    public_hostname: str = "localhost",
    tls_certificate: str | None = None,
    tls_private_key: str | None = None,
) -> RunningSite:
    if not tls_certificate or not tls_private_key:
        raise ValueError("Agent Web sites require a TLS certificate and private key")
    port = port or find_free_port(host)
    base_url = f"https://{public_hostname}:{port}"
    app = app_factory(base_url)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host=host,
            port=port,
            log_level="warning",
            access_log=False,
            ssl_certfile=tls_certificate,
            ssl_keyfile=tls_private_key,
        )
    )
    thread = Thread(target=server.run, name=f"agent-web-{port}", daemon=True)
    thread.start()
    deadline = monotonic() + 10
    while not server.started and thread.is_alive() and monotonic() < deadline:
        sleep(0.01)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=2)
        raise RuntimeError(f"Agent Web site failed to start on {base_url}")
    return RunningSite(app, server, thread, base_url)
