"""Render a digest-pinned, single-writer Kubernetes Agent Web deployment."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
SERVICES = {
    "moltbook": {"module": "moltbook_site.cli", "port": 8443},
    "forecast": {"module": "forecast_site.cli", "port": 8543},
    "registry": {"module": "registry_site", "port": 8643},
}
DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
IMAGE_BY_DIGEST = re.compile(
    r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$",
    re.IGNORECASE,
)
QUANTITY = re.compile(r"^[1-9][0-9]*(?:m|Ki|Mi|Gi|Ti)?$")
RESERVED_SUFFIXES = (".example", ".invalid", ".localhost", ".test")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _dns_name(value: Any, label: str) -> str:
    name = _string(value, label)
    if len(name) > 63 or not DNS_LABEL.fullmatch(name):
        raise ValueError(f"{label} must be a Kubernetes DNS label")
    return name


def _secret_key(value: Any, label: str) -> str:
    key = _string(value, label)
    if "/" in key or "\\" in key or key in {".", ".."}:
        raise ValueError(f"{label} must be one Secret data key")
    return key


def _relative_file(value: Any, label: str) -> str:
    raw = _string(value, label)
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts or raw.endswith("/"):
        raise ValueError(f"{label} must be a contained relative file path")
    return raw


def _public_base_url(value: Any, label: str, *, allow_example: bool) -> str:
    url = _string(value, label).rstrip("/")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{label} must be an origin-only HTTPS URL")
    hostname = parsed.hostname.casefold()
    if not allow_example and (
        hostname == "localhost"
        or hostname.endswith(RESERVED_SUFFIXES)
        or "." not in hostname
    ):
        raise ValueError(f"{label} must use an operator-controlled public hostname")
    return url


def _quantity(value: Any, label: str) -> str:
    result = _string(value, label)
    if not QUANTITY.fullmatch(result):
        raise ValueError(f"{label} is not a supported Kubernetes quantity")
    return result


def load_config(path: str | Path, *, allow_example: bool = False) -> dict[str, Any]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    return validate_config(document, allow_example=allow_example)


def validate_config(
    document: Mapping[str, Any], *, allow_example: bool = False
) -> dict[str, Any]:
    config = deepcopy(_object(dict(document), "deployment"))
    if config.get("schema") != "agent-web-kubernetes-deployment/1":
        raise ValueError("unsupported Kubernetes deployment schema")
    namespace = _dns_name(config.get("namespace"), "namespace")
    image = _string(config.get("runtimeImage"), "runtimeImage")
    if not IMAGE_BY_DIGEST.fullmatch(image):
        raise ValueError("runtimeImage must be an immutable sha256 OCI reference")
    if not allow_example and any(part in image.casefold() for part in RESERVED_SUFFIXES):
        raise ValueError("runtimeImage must use an operator-controlled registry")
    storage_class = config.get("storageClassName")
    if storage_class is not None:
        _dns_name(storage_class, "storageClassName")

    services = _object(config.get("services"), "services")
    if set(services) != set(SERVICES):
        raise ValueError("services must contain exactly moltbook, forecast, and registry")
    seen_hosts: set[str] = set()
    seen_secret_roles: dict[str, set[str]] = {
        "identity": set(),
        "tls": set(),
        "operations": set(),
        "vault-token": set(),
    }
    for name in SERVICES:
        service = _object(services[name], f"services.{name}")
        base_url = _public_base_url(
            service.get("baseUrl"), f"services.{name}.baseUrl", allow_example=allow_example
        )
        host = urlsplit(base_url).hostname.casefold()  # type: ignore[union-attr]
        if host in seen_hosts:
            raise ValueError("publisher base URLs must use distinct hostnames")
        seen_hosts.add(host)
        service["baseUrl"] = base_url
        service["storage"] = _quantity(service.get("storage"), f"services.{name}.storage")
        resources = _object(service.get("resources"), f"services.{name}.resources")
        for group in ("requests", "limits"):
            values = _object(resources.get(group), f"services.{name}.resources.{group}")
            if set(values) != {"cpu", "memory"}:
                raise ValueError(f"services.{name}.resources.{group} must set cpu and memory")
            _quantity(values["cpu"], f"services.{name}.resources.{group}.cpu")
            _quantity(values["memory"], f"services.{name}.resources.{group}.memory")

        for role in ("tls", "operations"):
            record = _object(service.get(role), f"services.{name}.{role}")
            secret_name = _dns_name(
                record.get("secretName"), f"services.{name}.{role}.secretName"
            )
            if secret_name in seen_secret_roles[role]:
                raise ValueError(f"{role} Secrets must be distinct per publisher")
            seen_secret_roles[role].add(secret_name)
        tls = service["tls"]
        for field in ("certificateKey", "privateKeyKey", "caKey"):
            _secret_key(tls.get(field), f"services.{name}.tls.{field}")
        operations = service["operations"]
        for field in ("metricsTokenKey", "operatorTokenKey"):
            _secret_key(operations.get(field), f"services.{name}.operations.{field}")

        identity = _object(service.get("identity"), f"services.{name}.identity")
        identity_secret = _dns_name(
            identity.get("secretName"), f"services.{name}.identity.secretName"
        )
        if identity_secret in seen_secret_roles["identity"]:
            raise ValueError("identity Secrets must be distinct per publisher")
        seen_secret_roles["identity"].add(identity_secret)
        mode = identity.get("mode")
        if mode == "local-lifecycle":
            items = identity.get("items")
            if not isinstance(items, list) or not items:
                raise ValueError(f"services.{name}.identity.items must be a non-empty list")
            paths: set[str] = set()
            for index, item_value in enumerate(items):
                item = _object(item_value, f"services.{name}.identity.items[{index}]")
                _secret_key(item.get("key"), f"services.{name}.identity.items[{index}].key")
                path = _relative_file(
                    item.get("path"), f"services.{name}.identity.items[{index}].path"
                )
                if path in paths:
                    raise ValueError("identity item paths must be unique")
                paths.add(path)
            if "manifest.json" not in paths:
                raise ValueError("local lifecycle identity must project manifest.json")
        elif mode == "vault-transit":
            for field in ("didDocumentKey", "accessTokenPrivateKeyKey"):
                _secret_key(identity.get(field), f"services.{name}.identity.{field}")
            vault = _object(service.get("vault"), f"services.{name}.vault")
            vault_url = _public_base_url(
                vault.get("url"), f"services.{name}.vault.url", allow_example=True
            )
            if not allow_example and urlsplit(vault_url).hostname in {"localhost", "127.0.0.1"}:
                raise ValueError("Vault URL must not be loopback")
            vault["url"] = vault_url
            _string(vault.get("mount"), f"services.{name}.vault.mount")
            _string(vault.get("key"), f"services.{name}.vault.key")
            token_secret = _dns_name(
                vault.get("tokenSecretName"), f"services.{name}.vault.tokenSecretName"
            )
            if token_secret in seen_secret_roles["vault-token"]:
                raise ValueError("Vault token Secrets must be distinct per publisher")
            seen_secret_roles["vault-token"].add(token_secret)
            _secret_key(vault.get("tokenKey"), f"services.{name}.vault.tokenKey")
            ca_secret = vault.get("caSecretName")
            ca_key = vault.get("caKey")
            if (ca_secret is None) != (ca_key is None):
                raise ValueError("Vault caSecretName and caKey must be supplied together")
            if ca_secret is not None:
                _dns_name(ca_secret, f"services.{name}.vault.caSecretName")
                _secret_key(ca_key, f"services.{name}.vault.caKey")
        else:
            raise ValueError(
                f"services.{name}.identity.mode must be local-lifecycle or vault-transit"
            )
    config["namespace"] = namespace
    return config


def _secret_volume(name: str, secret_name: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "name": name,
        "secret": {
            "secretName": secret_name,
            "defaultMode": 288,
            "items": [{**item, "mode": 288} for item in items],
        },
    }


def _probe(port: int, host: str, path: str, **timing: int) -> dict[str, Any]:
    code = (
        "import ssl,urllib.request;"
        "c=ssl.create_default_context(cafile='/run/agent-web/tls/ca.pem');"
        "c.check_hostname=False;"
        f"r=urllib.request.Request('https://127.0.0.1:{port}{path}',"
        f"headers={{'Host':'{host}'}});"
        "urllib.request.urlopen(r,context=c,timeout=3).read(1024)"
    )
    return {"exec": {"command": ["python", "-c", code]}, **timing}


def _identity_runtime(service: Mapping[str, Any]) -> tuple[list[str], list[dict[str, Any]], list[dict[str, Any]]]:
    identity = service["identity"]
    volumes: list[dict[str, Any]] = []
    mounts: list[dict[str, Any]] = []
    if identity["mode"] == "local-lifecycle":
        volumes.append(
            _secret_volume(
                "identity",
                identity["secretName"],
                [{"key": item["key"], "path": item["path"]} for item in identity["items"]],
            )
        )
        mounts.append({"name": "identity", "mountPath": "/run/agent-web/identity", "readOnly": True})
        return ["--identity-directory", "/run/agent-web/identity"], volumes, mounts

    vault = service["vault"]
    volumes.extend(
        [
            _secret_volume(
                "identity",
                identity["secretName"],
                [
                    {"key": identity["didDocumentKey"], "path": "did.json"},
                    {
                        "key": identity["accessTokenPrivateKeyKey"],
                        "path": "access-token-key.pem",
                    },
                ],
            ),
            _secret_volume(
                "vault-token",
                vault["tokenSecretName"],
                [{"key": vault["tokenKey"], "path": "token"}],
            ),
        ]
    )
    mounts.extend(
        [
            {"name": "identity", "mountPath": "/run/agent-web/identity", "readOnly": True},
            {"name": "vault-token", "mountPath": "/run/agent-web/vault", "readOnly": True},
        ]
    )
    args = [
        "--did-document", "/run/agent-web/identity/did.json",
        "--access-token-private-key", "/run/agent-web/identity/access-token-key.pem",
        "--vault-url", vault["url"],
        "--vault-mount", vault["mount"],
        "--vault-key", vault["key"],
        "--vault-token-file", "/run/agent-web/vault/token",
    ]
    if vault.get("caSecretName"):
        volumes.append(
            _secret_volume(
                "vault-ca",
                vault["caSecretName"],
                [{"key": vault["caKey"], "path": "ca.pem"}],
            )
        )
        mounts.append({"name": "vault-ca", "mountPath": "/run/agent-web/vault-ca", "readOnly": True})
        args.extend(["--vault-ca-file", "/run/agent-web/vault-ca/ca.pem"])
    return args, volumes, mounts


def _publisher_args(name: str, config: Mapping[str, Any]) -> list[str]:
    service = config["services"][name]
    port = SERVICES[name]["port"]
    args = [
        SERVICES[name]["module"],
        *(["serve"] if name == "registry" else []),
        "--host", "0.0.0.0",
        "--port", str(port),
        "--base-url", service["baseUrl"],
    ]
    if name == "moltbook":
        args.extend(
            [
                "--database", "/var/lib/agent-web/content.db",
                "--nonce-database", "/var/lib/agent-web/nonces.db",
                "--authorization-database", "/var/lib/agent-web/authorization.db",
                "--handle-database", "/var/lib/agent-web/wns.db",
                "--forecast-entrypoint",
                f"{config['services']['forecast']['baseUrl']}/forecast/resources/index.json",
            ]
        )
    elif name == "forecast":
        args.extend(
            [
                "--nonce-database", "/var/lib/agent-web/nonces.db",
                "--handle-database", "/var/lib/agent-web/wns.db",
                "--moltbook-entrypoint",
                f"{config['services']['moltbook']['baseUrl']}/moltbook/resources/index.json",
            ]
        )
    else:
        args.extend(
            [
                "--database", "/var/lib/agent-web/registry.db",
                "--nonce-database", "/var/lib/agent-web/nonces.db",
                "--handle-database", "/var/lib/agent-web/wns.db",
            ]
        )
    args.extend(
        [
            "--tls-certificate", "/run/agent-web/tls/cert.pem",
            "--tls-private-key", "/run/agent-web/tls/key.pem",
            "--metrics-token-file", "/run/agent-web/operations/metrics.token",
            "--operator-token-file", "/run/agent-web/operations/operator.token",
        ]
    )
    return args


def _publisher_resources(name: str, config: Mapping[str, Any]) -> list[dict[str, Any]]:
    namespace = config["namespace"]
    service = config["services"][name]
    port = SERVICES[name]["port"]
    labels = {
        "app.kubernetes.io/name": name,
        "app.kubernetes.io/component": name,
        "app.kubernetes.io/part-of": "agent-web",
    }
    identity_args, identity_volumes, identity_mounts = _identity_runtime(service)
    tls = service["tls"]
    operations = service["operations"]
    volumes = [
        {"name": "data", "persistentVolumeClaim": {"claimName": f"{name}-data"}},
        {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}},
        _secret_volume(
            "tls",
            tls["secretName"],
            [
                {"key": tls["certificateKey"], "path": "cert.pem"},
                {"key": tls["privateKeyKey"], "path": "key.pem"},
                {"key": tls["caKey"], "path": "ca.pem"},
            ],
        ),
        _secret_volume(
            "operations",
            operations["secretName"],
            [
                {"key": operations["metricsTokenKey"], "path": "metrics.token"},
                {"key": operations["operatorTokenKey"], "path": "operator.token"},
            ],
        ),
        *identity_volumes,
    ]
    mounts = [
        {"name": "data", "mountPath": "/var/lib/agent-web"},
        {"name": "tmp", "mountPath": "/tmp"},
        {"name": "tls", "mountPath": "/run/agent-web/tls", "readOnly": True},
        {"name": "operations", "mountPath": "/run/agent-web/operations", "readOnly": True},
        *identity_mounts,
    ]
    base_host = urlsplit(service["baseUrl"]).netloc
    container = {
        "name": name,
        "image": config["runtimeImage"],
        "imagePullPolicy": "IfNotPresent",
        "args": [*_publisher_args(name, config), *identity_args],
        "ports": [{"name": "https", "containerPort": port, "protocol": "TCP"}],
        "resources": deepcopy(service["resources"]),
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "privileged": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        },
        "startupProbe": _probe(port, base_host, "/live", periodSeconds=5, failureThreshold=24, timeoutSeconds=4),
        "livenessProbe": _probe(port, base_host, "/live", periodSeconds=30, failureThreshold=3, timeoutSeconds=4),
        "readinessProbe": _probe(port, base_host, "/ready", periodSeconds=10, failureThreshold=3, timeoutSeconds=4),
        "volumeMounts": mounts,
    }
    pod_spec = {
        "serviceAccountName": name,
        "automountServiceAccountToken": False,
        "enableServiceLinks": False,
        "os": {"name": "linux"},
        "nodeSelector": {"kubernetes.io/arch": "amd64"},
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 10001,
            "runAsGroup": 10001,
            "fsGroup": 10001,
            "fsGroupChangePolicy": "OnRootMismatch",
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "terminationGracePeriodSeconds": 60,
        "containers": [container],
        "volumes": volumes,
    }
    pvc_spec: dict[str, Any] = {
        "accessModes": ["ReadWriteOncePod"],
        "resources": {"requests": {"storage": service["storage"]}},
    }
    if config.get("storageClassName"):
        pvc_spec["storageClassName"] = config["storageClassName"]
    return [
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": name, "namespace": namespace, "labels": labels},
            "automountServiceAccountToken": False,
        },
        {
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {"name": f"{name}-data", "namespace": namespace, "labels": labels},
            "spec": pvc_spec,
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": name, "namespace": namespace, "labels": labels},
            "spec": {
                "replicas": 1,
                "strategy": {"type": "Recreate"},
                "revisionHistoryLimit": 3,
                "selector": {"matchLabels": labels},
                "template": {"metadata": {"labels": labels}, "spec": pod_spec},
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": name, "namespace": namespace, "labels": labels},
            "spec": {
                "type": "ClusterIP",
                "selector": labels,
                "ports": [{"name": "https", "port": 443, "targetPort": "https", "protocol": "TCP"}],
            },
        },
    ]


def render(config: Mapping[str, Any], *, allow_example: bool = False) -> dict[str, Any]:
    checked = validate_config(config, allow_example=allow_example)
    namespace = checked["namespace"]
    items: list[dict[str, Any]] = [
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": namespace,
                "labels": {
                    "kubernetes.io/metadata.name": namespace,
                    "pod-security.kubernetes.io/enforce": "restricted",
                    "pod-security.kubernetes.io/enforce-version": "latest",
                    "pod-security.kubernetes.io/audit": "restricted",
                    "pod-security.kubernetes.io/warn": "restricted",
                },
            },
        }
    ]
    for name in SERVICES:
        items.extend(_publisher_resources(name, checked))
    network = json.loads(
        (ROOT / "deploy/kubernetes/network-policies.json").read_text(encoding="utf-8")
    )
    for policy in network["items"]:
        policy = deepcopy(policy)
        policy["metadata"]["namespace"] = namespace
        items.append(policy)
    return {"apiVersion": "v1", "kind": "List", "items": items}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render hardened Agent Web Kubernetes resources"
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--allow-example",
        action="store_true",
        help="allow reserved example domains; never use for a real deployment",
    )
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    config = load_config(args.config, allow_example=args.allow_example)
    document = render(config, allow_example=args.allow_example)
    output = Path(args.output)
    if output.exists() and not args.force:
        raise FileExistsError(f"refusing to overwrite Kubernetes output: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": "rendered", "output": str(output), "resources": len(document["items"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
