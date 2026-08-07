"""Offline operator CLI for Agent Web authorization grants."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
from typing import Any

from .authorization import AuthorizationStore


def _datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("timestamp must include a timezone")
    return parsed


def _emit(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Manage operator-issued Agent Web authorization grants"
    )
    parser.add_argument(
        "--database",
        required=True,
        help="SQLite authorization database used by the publisher",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    grant = commands.add_parser("grant", help="issue a scoped grant")
    grant.add_argument("--subject", required=True, help="exact did:wba subject")
    grant.add_argument("--action", required=True, help="exact action name")
    grant.add_argument("--resource", required=True, help="HTTPS resource scope")
    grant.add_argument(
        "--scope",
        choices=("exact", "prefix"),
        default="exact",
    )
    grant.add_argument("--expires-at", type=_datetime)
    grant.add_argument("--max-uses", type=int)
    grant.add_argument("--note", default="")

    revoke = commands.add_parser("revoke", help="revoke an active grant")
    revoke.add_argument("grant_id")
    commands.add_parser("list", help="list grants")
    audit = commands.add_parser("audit", help="show authorization decisions")
    audit.add_argument("--limit", type=int, default=100)

    args = parser.parse_args()
    database = Path(args.database)
    database.parent.mkdir(parents=True, exist_ok=True)
    store = AuthorizationStore(database)
    try:
        if args.command == "grant":
            grant_id = store.grant(
                subject_did=args.subject,
                action=args.action,
                resource=args.resource,
                scope_type=args.scope,
                expires_at=args.expires_at,
                max_uses=args.max_uses,
                note=args.note,
            )
            _emit({"grantId": grant_id, "status": "issued"})
        elif args.command == "revoke":
            revoked = store.revoke(args.grant_id)
            _emit(
                {
                    "grantId": args.grant_id,
                    "status": "revoked" if revoked else "not-active",
                }
            )
        elif args.command == "list":
            _emit(store.list_grants())
        else:
            _emit(store.audit_log(limit=args.limit))
    finally:
        store.close()


if __name__ == "__main__":
    main()
