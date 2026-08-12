"""Collect live Kubernetes rollout evidence and optionally execute CNI probes."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any, Mapping
from uuid import uuid4

from render_kubernetes import SERVICES, load_config


REQUIRED_POLICIES = {
    "agent-web-default-deny",
    "agent-web-gateway-ingress",
    "agent-web-dns-egress",
    "forecast-public-https-egress",
    "registry-indexer-public-https-egress",
    "agent-web-vault-egress",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _job(
    *, namespace: str, image: str, name: str, component: str, code: str
) -> dict[str, Any]:
    labels = {
        "app.kubernetes.io/name": name,
        "app.kubernetes.io/component": component,
        "app.kubernetes.io/part-of": "agent-web",
        "agent-web.io/probe": "true",
    }
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": 45,
            "ttlSecondsAfterFinished": 300,
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "restartPolicy": "Never",
                    "serviceAccountName": component,
                    "automountServiceAccountToken": False,
                    "enableServiceLinks": False,
                    "os": {"name": "linux"},
                    "nodeSelector": {"kubernetes.io/arch": "amd64"},
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 10001,
                        "runAsGroup": 10001,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": "probe",
                            "image": image,
                            "imagePullPolicy": "IfNotPresent",
                            "command": ["python", "-c", code],
                            "resources": {
                                "requests": {"cpu": "10m", "memory": "32Mi"},
                                "limits": {"cpu": "100m", "memory": "128Mi"},
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "privileged": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                        }
                    ],
                },
            },
        },
    }


def build_network_probe_jobs(config: Mapping[str, Any], suffix: str = "contract") -> list[dict[str, Any]]:
    namespace = config["namespace"]
    image = config["runtimeImage"]
    allowed_public = (
        "import urllib.request;"
        "urllib.request.urlopen("
        "'https://api.open-meteo.com/v1/forecast?latitude=0&longitude=0&current=temperature_2m',"
        "timeout=15).read(1024);print('allowed-public:passed')"
    )
    denied_private = (
        "import os,socket,sys;"
        "host=os.environ.get('KUBERNETES_SERVICE_HOST','10.0.0.1');"
        "s=socket.socket();s.settimeout(3);"
        "\ntry:s.connect((host,443))\n"
        "except OSError:print('denied-private:passed');sys.exit(0)\n"
        "else:print('denied-private:failed');sys.exit(1)"
    )
    denied_public = (
        "import sys,urllib.request;"
        "\ntry:urllib.request.urlopen("
        "'https://api.open-meteo.com/v1/forecast?latitude=0&longitude=0&current=temperature_2m',"
        "timeout=5).read(1)\n"
        "except Exception:print('denied-unselected-public:passed');sys.exit(0)\n"
        "else:print('denied-unselected-public:failed');sys.exit(1)"
    )
    return [
        _job(
            namespace=namespace,
            image=image,
            name=f"agent-web-allow-public-{suffix}",
            component="forecast",
            code=allowed_public,
        ),
        _job(
            namespace=namespace,
            image=image,
            name=f"agent-web-deny-private-{suffix}",
            component="forecast",
            code=denied_private,
        ),
        _job(
            namespace=namespace,
            image=image,
            name=f"agent-web-deny-public-{suffix}",
            component="moltbook",
            code=denied_public,
        ),
    ]


class Kubectl:
    def __init__(self, executable: str, context: str, namespace: str) -> None:
        self.executable = executable
        self.context = context
        self.namespace = namespace

    def run(
        self,
        arguments: list[str],
        *,
        input_document: Mapping[str, Any] | None = None,
        timeout: int = 60,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        command = [self.executable, "--context", self.context, *arguments]
        return subprocess.run(
            command,
            input=(json.dumps(input_document) if input_document is not None else None),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=check,
        )

    def get(self, kind: str, name: str | None = None) -> dict[str, Any]:
        args = ["get", kind]
        if name:
            args.append(name)
        args.extend(["--namespace", self.namespace, "-o", "json"])
        return json.loads(self.run(args).stdout)


def _condition_ready(pod: Mapping[str, Any]) -> bool:
    return any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in pod.get("status", {}).get("conditions", [])
    )


def collect_cluster_evidence(client: Kubectl, config: Mapping[str, Any]) -> dict[str, Any]:
    server_version = json.loads(client.run(["version", "-o", "json"]).stdout)
    namespace = client.get("namespace", config["namespace"])
    deployments = client.get("deployments")
    pods = client.get("pods", "")
    pvcs = client.get("persistentvolumeclaims")
    policies = client.get("networkpolicies")
    endpoints = client.get("endpointslices.discovery.k8s.io")
    deployment_by_name = {item["metadata"]["name"]: item for item in deployments["items"]}
    if set(deployment_by_name) != set(SERVICES):
        raise ValueError("live cluster does not contain exactly the three Agent Web deployments")
    rollout: dict[str, Any] = {}
    for name in SERVICES:
        item = deployment_by_name[name]
        spec = item["spec"]
        status = item.get("status", {})
        if (
            spec.get("replicas") != 1
            or spec.get("strategy") != {"type": "Recreate"}
            or status.get("readyReplicas") != 1
            or status.get("updatedReplicas") != 1
            or status.get("unavailableReplicas", 0) != 0
            or status.get("observedGeneration", 0) < item["metadata"].get("generation", 0)
        ):
            raise ValueError(f"{name} rollout is not fully available and observed")
        image = spec["template"]["spec"]["containers"][0]["image"]
        if image != config["runtimeImage"]:
            raise ValueError(f"{name} runtime image differs from the accepted config")
        rollout[name] = {
            "generation": item["metadata"].get("generation"),
            "readyReplicas": status.get("readyReplicas"),
            "image": image,
        }
    selected_pods = [
        pod
        for pod in pods["items"]
        if pod.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/part-of") == "agent-web"
        and pod.get("metadata", {}).get("labels", {}).get("agent-web.io/probe") != "true"
    ]
    if len(selected_pods) != 3 or not all(_condition_ready(pod) for pod in selected_pods):
        raise ValueError("expected three Ready publisher pods")
    pod_evidence = []
    for pod in sorted(selected_pods, key=lambda item: item["metadata"]["name"]):
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if len(statuses) != 1 or not statuses[0].get("ready"):
            raise ValueError("publisher pod container is not ready")
        image_id = statuses[0].get("imageID", "")
        digest = config["runtimeImage"].split("@", 1)[1]
        if digest not in image_id:
            raise ValueError("container runtime imageID does not match the configured digest")
        pod_evidence.append(
            {
                "name": pod["metadata"]["name"],
                "uid": pod["metadata"]["uid"],
                "node": pod["spec"].get("nodeName"),
                "imageID": image_id,
                "restartCount": statuses[0].get("restartCount"),
                "ready": True,
            }
        )
    pvc_evidence = {}
    for pvc in pvcs["items"]:
        name = pvc["metadata"]["name"]
        if name not in {f"{service}-data" for service in SERVICES}:
            continue
        if pvc.get("status", {}).get("phase") != "Bound" or pvc["spec"].get("accessModes") != ["ReadWriteOncePod"]:
            raise ValueError(f"{name} is not a Bound ReadWriteOncePod claim")
        pvc_evidence[name] = {
            "uid": pvc["metadata"]["uid"],
            "phase": "Bound",
            "volumeName": pvc["spec"].get("volumeName"),
        }
    if len(pvc_evidence) != 3:
        raise ValueError("live cluster is missing a publisher PVC")
    policy_names = {item["metadata"]["name"] for item in policies["items"]}
    if policy_names != REQUIRED_POLICIES:
        raise ValueError("live NetworkPolicy set is incomplete or contains surprises")
    ready_services = {
        item.get("metadata", {}).get("labels", {}).get("kubernetes.io/service-name")
        for item in endpoints["items"]
        if any(
            endpoint.get("conditions", {}).get("ready") is True
            for endpoint in item.get("endpoints", [])
        )
    }
    if not set(SERVICES).issubset(ready_services):
        raise ValueError("one or more publisher Services have no ready EndpointSlice")
    return {
        "serverVersion": server_version.get("serverVersion"),
        "namespace": {
            "name": namespace["metadata"]["name"],
            "uid": namespace["metadata"]["uid"],
            "podSecurityEnforced": namespace["metadata"].get("labels", {}).get(
                "pod-security.kubernetes.io/enforce"
            ),
        },
        "rollout": rollout,
        "pods": pod_evidence,
        "persistentVolumes": pvc_evidence,
        "networkPolicies": sorted(policy_names),
        "readyServices": sorted(set(SERVICES) & ready_services),
    }


def execute_network_probes(client: Kubectl, config: Mapping[str, Any]) -> list[dict[str, Any]]:
    suffix = uuid4().hex[:8]
    jobs = build_network_probe_jobs(config, suffix)
    results: list[dict[str, Any]] = []
    names: list[str] = []
    try:
        for job in jobs:
            name = job["metadata"]["name"]
            names.append(name)
            client.run(["create", "-f", "-"], input_document=job)
        for job in jobs:
            name = job["metadata"]["name"]
            client.run(
                ["wait", "--namespace", client.namespace, "--for=condition=complete", f"job/{name}", "--timeout=60s"],
                timeout=75,
            )
            result = client.get("job", name)
            logs = client.run(["logs", "--namespace", client.namespace, f"job/{name}"]).stdout.strip()
            if result.get("status", {}).get("succeeded") != 1 or not logs.endswith(":passed"):
                raise ValueError(f"network probe did not pass: {name}")
            results.append({"name": name, "result": logs})
        return results
    finally:
        if names:
            client.run(
                ["delete", "jobs", "--namespace", client.namespace, *names, "--ignore-not-found=true", "--wait=true"],
                check=False,
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--execute-network-probes", action="store_true")
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--allow-example", action="store_true")
    args = parser.parse_args()
    config = load_config(args.config, allow_example=args.allow_example)
    output = Path(args.output)
    if output.exists():
        raise FileExistsError(f"refusing to overwrite Kubernetes evidence: {output}")
    if args.validate_only:
        jobs = build_network_probe_jobs(config)
        print(json.dumps({"status": "validated", "networkProbeJobs": len(jobs)}, indent=2))
        return 0
    kubectl = shutil.which("kubectl.exe") or shutil.which("kubectl")
    if kubectl is None:
        raise RuntimeError("kubectl is required for live Kubernetes acceptance")
    client = Kubectl(kubectl, args.context, config["namespace"])
    evidence = {
        "schema": "agent-web-kubernetes-live-evidence/1",
        "collectedAt": _utc_now(),
        "context": args.context,
        "cluster": collect_cluster_evidence(client, config),
        "networkPolicyExecuted": args.execute_network_probes,
        "networkProbes": (
            execute_network_probes(client, config) if args.execute_network_probes else []
        ),
        "claims": {
            "containerWorkloadsExecuted": True,
            "networkPolicyEnforcementExecuted": args.execute_network_probes,
            "publicIngressVerified": False,
            "managedKeyCustodyAttested": False,
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "output": str(output), "claims": evidence["claims"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
