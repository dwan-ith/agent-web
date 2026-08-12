"""Semantic checks for the rendered Agent Web Kubernetes workloads."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

from render_kubernetes import IMAGE_BY_DIGEST, SERVICES, load_config, render, validate_config
from kubernetes_live_gate import build_network_probe_jobs


ROOT = Path(__file__).resolve().parents[1]


def _expect_rejected(config: dict, message: str) -> None:
    try:
        validate_config(config, allow_example=True)
    except ValueError:
        return
    raise ValueError(f"unsafe configuration was accepted: {message}")


def main() -> int:
    config = load_config(
        ROOT / "deploy/kubernetes/deployment.example.json",
        allow_example=True,
    )
    document = render(config, allow_example=True)
    if document != render(config, allow_example=True):
        raise ValueError("Kubernetes rendering is not deterministic")
    items = document.get("items")
    if not isinstance(items, list):
        raise ValueError("rendered Kubernetes List is missing items")
    by_kind: dict[str, list[dict]] = {}
    for item in items:
        by_kind.setdefault(item["kind"], []).append(item)
    expected_counts = {
        "Namespace": 1,
        "ServiceAccount": 3,
        "PersistentVolumeClaim": 3,
        "Deployment": 3,
        "Service": 3,
        "NetworkPolicy": 6,
    }
    actual_counts = {kind: len(values) for kind, values in by_kind.items()}
    if actual_counts != expected_counts:
        raise ValueError(f"unexpected Kubernetes resources: {actual_counts}")
    namespace = by_kind["Namespace"][0]
    labels = namespace["metadata"]["labels"]
    if labels.get("pod-security.kubernetes.io/enforce") != "restricted":
        raise ValueError("namespace does not enforce the Restricted Pod Security Standard")

    pvcs = {item["metadata"]["name"]: item for item in by_kind["PersistentVolumeClaim"]}
    deployments = {item["metadata"]["name"]: item for item in by_kind["Deployment"]}
    cluster_services = {item["metadata"]["name"]: item for item in by_kind["Service"]}
    for name, service_contract in SERVICES.items():
        deployment = deployments[name]
        spec = deployment["spec"]
        if spec.get("replicas") != 1 or spec.get("strategy") != {"type": "Recreate"}:
            raise ValueError(f"{name} does not enforce one Recreate-managed writer")
        pod = spec["template"]["spec"]
        if pod.get("automountServiceAccountToken") is not False:
            raise ValueError(f"{name} mounts a Kubernetes API credential")
        if pod.get("nodeSelector") != {"kubernetes.io/arch": "amd64"}:
            raise ValueError(f"{name} can run outside the dependency-lock architecture")
        pod_security = pod.get("securityContext", {})
        if (
            pod_security.get("runAsNonRoot") is not True
            or pod_security.get("runAsUser") != 10001
            or pod_security.get("seccompProfile") != {"type": "RuntimeDefault"}
        ):
            raise ValueError(f"{name} pod security context is incomplete")
        if any("hostPath" in volume for volume in pod.get("volumes", [])):
            raise ValueError(f"{name} uses a hostPath")
        container = pod["containers"][0]
        if not IMAGE_BY_DIGEST.fullmatch(container.get("image", "")):
            raise ValueError(f"{name} image is not digest pinned")
        security = container.get("securityContext", {})
        if (
            security.get("allowPrivilegeEscalation") is not False
            or security.get("readOnlyRootFilesystem") is not True
            or security.get("capabilities") != {"drop": ["ALL"]}
        ):
            raise ValueError(f"{name} container security context is incomplete")
        if "env" in container or "envFrom" in container:
            raise ValueError(f"{name} passes configuration or secrets through environment")
        mounts = container.get("volumeMounts", [])
        for mount in mounts:
            if mount["name"] not in {"data", "tmp"} and mount.get("readOnly") is not True:
                raise ValueError(f"{name} has a writable secret mount")
        args = container.get("args", [])
        for required in (
            "--vault-token-file",
            "--metrics-token-file",
            "--operator-token-file",
            "--tls-private-key",
        ):
            if required not in args:
                raise ValueError(f"{name} is missing {required}")
        probes = {
            "startupProbe": "/live",
            "livenessProbe": "/live",
            "readinessProbe": "/ready",
        }
        for probe_name, endpoint in probes.items():
            command = " ".join(container[probe_name]["exec"]["command"])
            if endpoint not in command or "create_default_context" not in command:
                raise ValueError(f"{name} {probe_name} is not a CA-aware HTTPS probe")
        pvc = pvcs[f"{name}-data"]
        if pvc["spec"].get("accessModes") != ["ReadWriteOncePod"]:
            raise ValueError(f"{name} PVC does not enforce cluster-wide single-pod access")
        service = cluster_services[name]
        if service["spec"].get("type") != "ClusterIP":
            raise ValueError(f"{name} bypasses the operator ingress boundary")
        if service["spec"]["ports"] != [
            {"name": "https", "port": 443, "targetPort": "https", "protocol": "TCP"}
        ]:
            raise ValueError(f"{name} Service is not HTTPS-only")
        if container["ports"][0]["containerPort"] != service_contract["port"]:
            raise ValueError(f"{name} container port drifted from the runtime contract")

    for policy in by_kind["NetworkPolicy"]:
        if policy["metadata"].get("namespace") != config["namespace"]:
            raise ValueError("NetworkPolicy namespace does not match workloads")

    mutable = deepcopy(config)
    mutable["runtimeImage"] = "registry.example.invalid/agent-web-runtime:latest"
    _expect_rejected(mutable, "mutable runtime image")
    duplicate_host = deepcopy(config)
    duplicate_host["services"]["forecast"]["baseUrl"] = duplicate_host["services"]["moltbook"]["baseUrl"]
    _expect_rejected(duplicate_host, "duplicate publisher hostname")
    shared_secret = deepcopy(config)
    shared_secret["services"]["forecast"]["operations"]["secretName"] = shared_secret["services"]["moltbook"]["operations"]["secretName"]
    _expect_rejected(shared_secret, "shared operations Secret")

    probe_jobs = build_network_probe_jobs(config)
    if len(probe_jobs) != 3:
        raise ValueError("CNI acceptance must contain exactly three probes")
    expected_components = ["forecast", "forecast", "moltbook"]
    for job, component in zip(probe_jobs, expected_components, strict=True):
        pod = job["spec"]["template"]["spec"]
        labels = job["spec"]["template"]["metadata"]["labels"]
        if (
            labels.get("app.kubernetes.io/component") != component
            or labels.get("app.kubernetes.io/part-of") != "agent-web"
            or pod.get("automountServiceAccountToken") is not False
            or pod.get("nodeSelector") != {"kubernetes.io/arch": "amd64"}
            or pod["containers"][0]["image"] != config["runtimeImage"]
        ):
            raise ValueError("CNI probe does not exercise the selected workload policy safely")

    print(
        json.dumps(
            {
                "status": "passed",
                "resources": len(items),
                "publishers": sorted(deployments),
                "runtimeImageByDigest": True,
                "singleWriter": "Deployment replicas=1 + Recreate + ReadWriteOncePod",
                "podSecurity": "Restricted + non-root + RuntimeDefault seccomp",
                "liveExecution": "not asserted; run the cluster acceptance gate",
                "cniProbeContracts": len(probe_jobs),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
