"""Live public-CA, exact-WNS, object-proof, and federation acceptance gate."""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
from pathlib import Path
import socket
import ssl
from typing import Any, Mapping
from urllib.parse import urlsplit

from libagentweb import AgentBrowser, resolve_exact_handle


SCHEMA = "agent-web-public-beta/1"
ROLES = {"moltbook", "forecast", "registry"}


class _PublicReadOnlyAuth:
    """Marker auth object; the public gate never invokes protected actions."""


def validate_manifest(document: Mapping[str, Any]) -> list[dict[str, str]]:
    if document.get("schema") != SCHEMA:
        raise ValueError("unsupported public-beta manifest")
    operators = document.get("operators")
    if not isinstance(operators, list) or len(operators) < 2:
        raise ValueError("public beta requires at least two claimed operators")
    ids: set[str] = set()
    organizations: set[str] = set()
    sites: list[dict[str, str]] = []
    roles: set[str] = set()
    for operator in operators:
        if not isinstance(operator, Mapping):
            raise ValueError("operator entry must be an object")
        operator_id = operator.get("id")
        organization = operator.get("organization")
        contact = operator.get("securityContact")
        if (
            not isinstance(operator_id, str)
            or not operator_id
            or len(operator_id) > 64
            or operator_id in ids
        ):
            raise ValueError("operator ids must be unique bounded strings")
        if (
            not isinstance(organization, str)
            or not organization.strip()
            or len(organization) > 200
            or organization.casefold() in organizations
        ):
            raise ValueError("operator organizations must be distinct")
        if not isinstance(contact, str) or not contact.startswith(
            ("mailto:", "https://")
        ):
            raise ValueError("operator security contact must use mailto or HTTPS")
        ids.add(operator_id)
        organizations.add(organization.casefold())
        operator_sites = operator.get("sites")
        if not isinstance(operator_sites, list) or not operator_sites:
            raise ValueError("each operator must publish at least one site")
        for site in operator_sites:
            if not isinstance(site, Mapping):
                raise ValueError("site entry must be an object")
            role = site.get("role")
            handle = site.get("handle")
            description_url = site.get("agentDescriptionUrl")
            if role not in ROLES or role in roles:
                raise ValueError("manifest requires exactly one site for each role")
            if not isinstance(handle, str) or not handle or len(handle) > 253:
                raise ValueError("site handle is invalid")
            parsed = urlsplit(str(description_url))
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("Agent Description URL must use absolute HTTPS")
            _local, separator, handle_domain = handle.partition(".")
            if not separator or handle_domain.casefold() != parsed.hostname.casefold():
                raise ValueError("handle domain must equal Agent Description host")
            roles.add(role)
            sites.append(
                {
                    "operatorId": operator_id,
                    "organization": organization,
                    "securityContact": contact,
                    "role": role,
                    "handle": handle,
                    "agentDescriptionUrl": str(description_url),
                }
            )
    if roles != ROLES:
        raise ValueError("manifest must contain Moltbook, Forecast, and Registry")
    if len({site["operatorId"] for site in sites}) < 2:
        raise ValueError("site roles must span at least two claimed operators")
    return sites


async def run_gate(document: Mapping[str, Any], *, timeout: float) -> dict[str, Any]:
    sites = validate_manifest(document)
    evidence: dict[str, dict[str, Any]] = {}
    certificates: dict[str, dict[str, Any]] = {}
    for site in sites:
        parsed = urlsplit(site["agentDescriptionUrl"])
        hostname = parsed.hostname
        assert hostname is not None
        _require_public_hostname(hostname)
        if hostname not in certificates:
            certificates[hostname] = await asyncio.to_thread(
                _certificate_evidence,
                hostname,
                parsed.port or 443,
                timeout,
            )
        binding = await resolve_exact_handle(
            site["handle"],
            timeout=timeout,
            allow_private_networks=False,
        )
        endpoints = {
            service.get("serviceEndpoint")
            for service in binding.did_document.get("service", [])
            if isinstance(service, Mapping)
            and service.get("type") == "AgentDescription"
        }
        if endpoints != {site["agentDescriptionUrl"]}:
            raise ValueError(
                f"{site['role']} WNS DID does not authorize the declared description"
            )
        browser = AgentBrowser(
            site["agentDescriptionUrl"],
            auth_header=_PublicReadOnlyAuth(),  # type: ignore[arg-type]
            timeout=timeout,
            allow_private_networks=False,
        )
        description = await browser.discover_async()
        entrypoint = description.get("agentWeb", {}).get("entryPoint")
        if not isinstance(entrypoint, str):
            raise ValueError(f"{site['role']} description has no Agent Web entry point")
        resource = await browser.open_async(entrypoint)
        evidence[site["role"]] = {
            **site,
            "did": binding.did,
            "bindingGeneration": binding.binding_generation,
            "entryPoint": entrypoint,
            "entryResource": resource["@id"],
            "entryProofVerificationMethod": resource["proof"]["verificationMethod"],
            "descriptionProofVerificationMethod": description["proof"][
                "verificationMethod"
            ],
            "resource": resource,
        }
    _verify_federation(evidence)
    public_evidence = {
        role: {key: value for key, value in record.items() if key != "resource"}
        for role, record in evidence.items()
    }
    return {
        "schema": "agent-web-public-beta-evidence/1",
        "checkedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "status": "passed",
        "sites": public_evidence,
        "certificates": certificates,
        "crossOperatorFederation": True,
        "operatorIndependence": (
            "manifest-asserted only; legal and operational independence requires "
            "external reviewer verification"
        ),
        "externalSecurityReview": "not established by this gate",
    }


def _verify_federation(evidence: Mapping[str, Mapping[str, Any]]) -> None:
    moltbook = evidence["moltbook"]
    forecast = evidence["forecast"]
    registry = evidence["registry"]
    if moltbook["operatorId"] == forecast["operatorId"]:
        raise ValueError("Moltbook and Forecast must be cross-operator for this gate")
    molt_links = {
        link.get("href") for link in moltbook["resource"].get("links", [])
        if isinstance(link, Mapping) and link.get("rel") == "related"
    }
    forecast_links = {
        link.get("href") for link in forecast["resource"].get("links", [])
        if isinstance(link, Mapping) and link.get("rel") == "related"
    }
    if forecast["entryPoint"] not in molt_links:
        raise ValueError("Moltbook does not link the independent Forecast entry point")
    if moltbook["entryPoint"] not in forecast_links:
        raise ValueError("Forecast does not link the independent Moltbook entry point")
    registry_dids = {
        site.get("publisher")
        for site in registry["resource"].get("data", {}).get("sites", [])
        if isinstance(site, Mapping)
    }
    required = {moltbook["did"], forecast["did"]}
    if not required.issubset(registry_dids):
        raise ValueError("Registry has not indexed both independent publishers")


def _require_public_hostname(hostname: str) -> None:
    lowered = hostname.casefold().rstrip(".")
    if lowered.endswith((".example", ".test", ".invalid", ".localhost", ".local")):
        raise ValueError(f"placeholder or private hostname is not public: {hostname}")
    try:
        ipaddress.ip_address(lowered)
    except ValueError:
        if "." not in lowered:
            raise ValueError(f"single-label hostname is not public: {hostname}")
    else:
        raise ValueError("public beta manifest must use DNS names, not IP literals")


def _certificate_evidence(hostname: str, port: int, timeout: float) -> dict[str, Any]:
    context = ssl.create_default_context()
    addresses = socket.getaddrinfo(
        hostname, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
    )
    if not addresses:
        raise ValueError(f"certificate hostname did not resolve: {hostname}")
    checked: list[tuple[int, int, int, tuple[Any, ...]]] = []
    for family, socktype, protocol, _canonical, address in addresses:
        parsed_address = ipaddress.ip_address(address[0])
        if not parsed_address.is_global:
            raise ValueError(
                f"certificate hostname resolved to a non-public address: {hostname}"
            )
        item = (family, socktype, protocol, address)
        if item not in checked:
            checked.append(item)
    family, socktype, protocol, address = checked[0]
    with socket.socket(family, socktype, protocol) as raw:
        raw.settimeout(timeout)
        raw.connect(address)
        with context.wrap_socket(raw, server_hostname=hostname) as secure:
            certificate = secure.getpeercert()
            der = secure.getpeercert(binary_form=True)
            protocol = secure.version()
            cipher = secure.cipher()
    not_after = certificate.get("notAfter")
    if not isinstance(not_after, str):
        raise ValueError(f"certificate for {hostname} has no expiry")
    expiry = datetime.fromtimestamp(
        ssl.cert_time_to_seconds(not_after), timezone.utc
    )
    if expiry <= datetime.now(timezone.utc):
        raise ValueError(f"certificate for {hostname} is expired")
    issuer = ", ".join(
        f"{key}={value}"
        for group in certificate.get("issuer", ())
        for key, value in group
    )
    return {
        "sha256": sha256(der).hexdigest(),
        "issuer": issuer,
        "serialNumber": certificate.get("serialNumber"),
        "notAfter": expiry.isoformat().replace("+00:00", "Z"),
        "tlsVersion": protocol,
        "cipher": cipher[0] if cipher else None,
        "hostnameVerifiedByDefaultTrustStore": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    document = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    sites = validate_manifest(document)
    if args.validate_only:
        print(json.dumps({"status": "passed", "sites": sites}, indent=2))
        return 0
    result = asyncio.run(run_gate(document, timeout=args.timeout))
    content = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8", newline="\n")
    print(content, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
