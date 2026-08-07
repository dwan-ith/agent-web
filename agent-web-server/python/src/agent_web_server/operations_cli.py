"""Command-line backup, verification, and restore operations."""

from __future__ import annotations

import argparse
import json
from typing import Any

from .operations import (
    create_backup_bundle,
    create_coordinated_backup_bundle,
    restore_backup_bundle,
    verify_backup_bundle,
)
from .secrets import read_secret_file


def _database(value: str) -> tuple[str, str]:
    name, separator, path = value.partition("=")
    if not separator or not name or not path:
        raise argparse.ArgumentTypeError("database must use NAME=PATH")
    return name, path


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent Web SQLite recovery tools")
    commands = parser.add_subparsers(dest="command", required=True)
    backup = commands.add_parser("backup")
    backup.add_argument("--database", action="append", type=_database, required=True)
    backup.add_argument("--destination", required=True)
    coordinated = commands.add_parser("coordinated-backup")
    coordinated.add_argument(
        "--database", action="append", type=_database, required=True
    )
    coordinated.add_argument("--destination", required=True)
    coordinated.add_argument("--maintenance-url", action="append", required=True)
    coordinated.add_argument("--operator-token-file", required=True)
    coordinated.add_argument("--ca-file")
    verify = commands.add_parser("verify")
    verify.add_argument("--bundle", required=True)
    restore = commands.add_parser("restore")
    restore.add_argument("--bundle", required=True)
    restore.add_argument("--destination", required=True)
    args = parser.parse_args()

    if args.command in {"backup", "coordinated-backup"}:
        databases = dict(args.database)
        if len(databases) != len(args.database):
            parser.error("database names must be unique")
        if args.command == "coordinated-backup":
            result: Any = create_coordinated_backup_bundle(
                databases,
                args.destination,
                maintenance_url=args.maintenance_url,
                operator_token=read_secret_file(args.operator_token_file),
                ca_file=args.ca_file,
            )
        else:
            result = create_backup_bundle(databases, args.destination)
    elif args.command == "verify":
        result = verify_backup_bundle(args.bundle)
    else:
        result = {
            name: str(path)
            for name, path in restore_backup_bundle(
                args.bundle,
                args.destination,
            ).items()
        }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
