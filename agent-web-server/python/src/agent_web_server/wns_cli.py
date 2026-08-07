"""Operator commands for WNS handle lifecycle changes."""

from __future__ import annotations

import argparse
import json

from anp.wns import HandleStatus

from .wns import HandleStore


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage Agent Web WNS handles")
    parser.add_argument("--database", required=True)
    parser.add_argument("--provider-domain", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    register = commands.add_parser("register")
    register.add_argument("--handle", required=True)
    register.add_argument("--did", required=True)
    rotate = commands.add_parser("rotate")
    rotate.add_argument("--handle", required=True)
    rotate.add_argument("--did", required=True)
    rotate.add_argument("--expect-did", required=True)
    status = commands.add_parser("status")
    status.add_argument("--handle", required=True)
    status.add_argument("--set", choices=[value.value for value in HandleStatus], required=True)
    status.add_argument("--expect-generation", required=True)
    show = commands.add_parser("show")
    show.add_argument("--local-part", required=True)
    history = commands.add_parser("history")
    history.add_argument("--handle", required=True)
    args = parser.parse_args()

    store = HandleStore(args.database, provider_domain=args.provider_domain)
    try:
        if args.command == "register":
            result = store.bind(args.handle, args.did).model_dump(
                mode="json", exclude_none=True
            )
        elif args.command == "rotate":
            result = store.bind(
                args.handle,
                args.did,
                expected_did=args.expect_did,
            ).model_dump(mode="json", exclude_none=True)
        elif args.command == "status":
            result = store.set_status(
                args.handle,
                args.set,
                expected_generation=args.expect_generation,
            ).model_dump(mode="json", exclude_none=True)
        elif args.command == "show":
            document = store.resolve(args.local_part)
            if document is None:
                raise SystemExit("handle not found")
            result = document.model_dump(mode="json", exclude_none=True)
        else:
            result = store.history(args.handle)
    finally:
        store.close()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
