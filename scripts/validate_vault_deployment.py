"""Static checks for the optional Vault-backed publisher override."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    document = json.loads(
        (ROOT / "deploy/compose.vault.json").read_text(encoding="utf-8")
    )
    services = document.get("services", {})
    if set(services) != {"moltbook", "forecast", "registry"}:
        raise ValueError("Vault override must configure all publishers")
    required = {
        "--did-document",
        "--access-token-private-key",
        "--vault-url",
        "--vault-mount",
        "--vault-key",
        "--vault-token-file",
    }
    for name, service in services.items():
        command = service.get("command", [])
        missing = required.difference(command)
        if missing:
            raise ValueError(f"{name} Vault command is missing {sorted(missing)}")
        if "--private-key" in command or "--identity-directory" in command:
            raise ValueError(f"{name} still requests a local publisher key")
        token_index = command.index("--vault-token-file") + 1
        if command[token_index] != "/run/agent-web/operations/vault.token":
            raise ValueError(f"{name} Vault token is not file-mounted")
    print(
        json.dumps(
            {
                "status": "passed",
                "services": sorted(services),
                "publisherPrivateKeyMounted": False,
                "liveVaultCustody": "requires verify_vault_signer.py evidence",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
