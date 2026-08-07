"""Operator CLI for durable Agent Web identity generations."""

from __future__ import annotations

import argparse
import json

from .identity import (
    PublisherIdentity,
    load_identity_manifest,
    provision_identity_lifecycle,
    rotate_identity_lifecycle,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Provision and rotate key-bound Agent Web identities"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    provision = commands.add_parser("provision")
    provision.add_argument("--directory", required=True)
    provision.add_argument("--base-url", required=True)
    provision.add_argument("--agent-name", required=True)
    provision.add_argument("--agent-description-path", required=True)
    provision.add_argument("--handle")
    rotate = commands.add_parser("rotate")
    rotate.add_argument("--directory", required=True)
    rotate.add_argument("--expect-did", required=True)
    status = commands.add_parser("status")
    status.add_argument("--directory", required=True)

    args = parser.parse_args()
    if args.command == "provision":
        identity = provision_identity_lifecycle(
            directory=args.directory,
            base_url=args.base_url,
            agent_name=args.agent_name,
            agent_description_path=args.agent_description_path,
            handle=args.handle,
        )
        result = {
            "status": "provisioned",
            "activeDid": identity.did,
            "manifest": f"{args.directory}/manifest.json",
        }
    elif args.command == "rotate":
        transition = rotate_identity_lifecycle(
            args.directory,
            expected_active_did=args.expect_did,
        )
        result = {"status": "rotated", "transition": transition}
    else:
        manifest = load_identity_manifest(args.directory)
        active = PublisherIdentity.from_lifecycle(args.directory)
        result = {
            "status": "active",
            "activeDid": active.did,
            "activeGeneration": manifest["activeGeneration"],
            "generations": [
                {
                    "generation": entry["generation"],
                    "did": entry["did"],
                    "status": entry["status"],
                }
                for entry in manifest["generations"]
            ],
        }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
