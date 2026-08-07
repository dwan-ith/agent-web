"""Module entry point for registry operator commands."""

from __future__ import annotations

import sys

from .cli import index, serve


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in {"serve", "index"}:
        raise SystemExit("usage: python -m registry_site {serve|index} [options]")
    command = sys.argv.pop(1)
    (serve if command == "serve" else index)()


if __name__ == "__main__":
    main()
