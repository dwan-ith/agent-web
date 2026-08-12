"""CLI for deterministic Agent Web wheel SBOM and provenance evidence."""

from __future__ import annotations

import argparse
import json

from release_evidence import generate_release_evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            generate_release_evidence(args.wheel_dir, args.output),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
