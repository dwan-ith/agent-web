"""Semantic static checks for the Kubernetes Agent Web network boundary."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_V4_EXCLUSIONS = {
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
}
REQUIRED_V6_EXCLUSIONS = {
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
}


def main() -> int:
    document = json.loads(
        (ROOT / "deploy/kubernetes/network-policies.json").read_text(
            encoding="utf-8"
        )
    )
    if document.get("kind") != "List":
        raise ValueError("network policy document must be a Kubernetes List")
    policies = document.get("items")
    if not isinstance(policies, list):
        raise ValueError("network policy items are missing")
    by_name = {item["metadata"]["name"]: item for item in policies}
    required = {
        "agent-web-default-deny",
        "agent-web-gateway-ingress",
        "agent-web-dns-egress",
        "forecast-public-https-egress",
        "registry-indexer-public-https-egress",
        "agent-web-vault-egress",
    }
    if set(by_name) != required:
        raise ValueError("network policy set is incomplete or contains surprises")
    default = by_name["agent-web-default-deny"]["spec"]
    if default.get("policyTypes") != ["Ingress", "Egress"]:
        raise ValueError("default deny must select ingress and egress")
    if default.get("ingress") != [] or default.get("egress") != []:
        raise ValueError("default deny policy unexpectedly permits traffic")
    dns = by_name["agent-web-dns-egress"]["spec"]["egress"]
    dns_ports = {
        (entry["protocol"], entry["port"])
        for entry in dns[0].get("ports", [])
    }
    if dns_ports != {("UDP", 53), ("TCP", 53)}:
        raise ValueError("DNS egress must be limited to TCP and UDP port 53")
    for name in (
        "forecast-public-https-egress",
        "registry-indexer-public-https-egress",
    ):
        rule = by_name[name]["spec"]["egress"]
        if rule[0].get("ports") != [{"protocol": "TCP", "port": 443}]:
            raise ValueError(f"{name} is not limited to TCP/443")
        blocks = {
            item["ipBlock"]["cidr"]: set(item["ipBlock"].get("except", []))
            for item in rule[0].get("to", [])
        }
        if not REQUIRED_V4_EXCLUSIONS.issubset(blocks.get("0.0.0.0/0", set())):
            raise ValueError(f"{name} does not exclude required IPv4 ranges")
        if not REQUIRED_V6_EXCLUSIONS.issubset(blocks.get("::/0", set())):
            raise ValueError(f"{name} does not exclude required IPv6 ranges")
        for cidr, exclusions in blocks.items():
            parent = ipaddress.ip_network(cidr)
            for excluded in exclusions:
                if not ipaddress.ip_network(excluded).subnet_of(parent):
                    raise ValueError(f"{excluded} is outside policy block {cidr}")
    vault = by_name["agent-web-vault-egress"]["spec"]["egress"]
    if vault[0].get("ports") != [{"protocol": "TCP", "port": 8200}]:
        raise ValueError("Vault egress must be limited to TCP/8200")
    print(
        json.dumps(
            {
                "status": "passed",
                "policies": sorted(by_name),
                "defaultDeny": True,
                "publicEgressWorkloads": ["forecast", "registry-indexer"],
                "enforcement": "requires a NetworkPolicy-capable CNI and live probes",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
