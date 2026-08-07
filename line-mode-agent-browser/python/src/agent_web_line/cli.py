"""Text-only Agent Web browser."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from libagentweb.browser import AgentBrowser, RemoteANPError
from libagentweb.resource import ResourceValidationError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-web",
        description="Line-mode Agent Web browser over official ANP",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    discover = commands.add_parser("discover", help="resolve a WNS handle or read an ANP Agent Description")
    discover.add_argument("url", help="WNS handle or HTTPS Agent Description URL")
    _identity_arguments(discover)

    open_resource = commands.add_parser("open", help="open an Agent Web resource")
    open_resource.add_argument("url")
    open_resource.add_argument("--description", required=True)
    _identity_arguments(open_resource)

    crawl = commands.add_parser("crawl", help="traverse a linked Agent Web site")
    crawl.add_argument("agent_description_url", help="WNS handle or HTTPS Agent Description URL")
    crawl.add_argument(
        "--allow-origin",
        action="append",
        default=[],
        help="additional HTTP(S) origin allowed during cross-site traversal",
    )
    _identity_arguments(crawl)

    call = commands.add_parser("call", help="invoke an ANP JSON-RPC method")
    call.add_argument("agent_description_url", help="WNS handle or HTTPS Agent Description URL")
    call.add_argument("method")
    call.add_argument("--params", default="{}", help="JSON object")
    call.add_argument(
        "--resource",
        help="resource advertising the action; defaults to the entry point",
    )
    call.add_argument(
        "--confirm",
        action="store_true",
        help="record explicit user presence for a high-risk action",
    )
    _identity_arguments(call)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "discover":
            result = _browser(args, args.url).discover()
        elif args.command == "open":
            result = _browser(args, args.description).open(args.url)
        elif args.command == "crawl":
            origins = set(args.allow_origin)
            browser = _browser(
                args,
                args.agent_description_url,
                allowed_origins=origins or None,
            )
            result = browser.traverse()
        else:
            params = json.loads(args.params)
            if not isinstance(params, dict):
                raise ValueError("--params must decode to a JSON object")
            result = _browser(args, args.agent_description_url).call(
                args.method,
                params,
                confirmed=args.confirm,
                resource_url=args.resource,
            )
        _print_json(result)
        return 0
    except (
        ConnectionError,
        PermissionError,
        RemoteANPError,
        ResourceValidationError,
        ValueError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--did-document",
        required=True,
        help="path to this browser's DID-WBA document",
    )
    parser.add_argument(
        "--private-key",
        required=True,
        help="path to this browser's Ed25519 private key",
    )
    parser.add_argument(
        "--allow-private-network",
        action="store_true",
        help="allow localhost/private origins for an explicit development network",
    )


def _browser(
    args: argparse.Namespace,
    description_url: str,
    *,
    allowed_origins: set[str] | None = None,
) -> AgentBrowser:
    if description_url.startswith("https://"):
        return AgentBrowser(
            description_url,
            did_document_path=args.did_document,
            private_key_path=args.private_key,
            allowed_origins=allowed_origins,
            allow_private_networks=args.allow_private_network,
        )
    browser = AgentBrowser.from_handle(
        description_url,
        did_document_path=args.did_document,
        private_key_path=args.private_key,
        allow_private_networks=args.allow_private_network,
    )
    browser.allowed_origins.update(allowed_origins or ())
    return browser


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    raise SystemExit(main())
