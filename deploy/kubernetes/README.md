# Kubernetes production contract

Agent Web has a renderer for the three publisher workloads as well as the
default-deny network boundary. The renderer accepts operator configuration and
emits a standard Kubernetes JSON `List`; it never generates or embeds secret
values.

## Safety model

The current stores are SQLite, so this deployment is deliberately
active-passive rather than active-active. Each publisher is constrained by all
three of these controls:

- one Deployment replica with the `Recreate` update strategy;
- one CSI-backed `ReadWriteOncePod` claim, which prevents a second pod anywhere
  in the cluster from mounting the database;
- a distinct data claim and distinct identity, TLS, operations-token, and Vault
  token Secrets.

[`ReadWriteOncePod`](https://kubernetes.io/docs/tasks/administer-cluster/change-pv-access-mode-readwriteoncepod/)
is stable in Kubernetes 1.29 and requires a compatible CSI driver. Do not weaken
it to `ReadWriteOnce`: that mode can allow two pods on one
node to mount the same volume. Availability comes from rescheduling the one
writer and restoring tested backups, not concurrent SQLite writers.

The namespace enforces the Kubernetes
[Restricted Pod Security Standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/).
Containers run as
UID/GID 10001 with a read-only root filesystem, all capabilities dropped,
privilege escalation disabled, RuntimeDefault seccomp, no service-account token,
resource bounds, memory-backed `/tmp`, CA-aware local HTTPS probes, and an image
reference that must include a `sha256` digest. A Linux/amd64 node selector keeps
the workload on the architecture covered by `deploy/requirements.lock`.

## Render and apply

Copy `deployment.example.json` outside the repository and replace every
reserved domain, Secret name, storage class, Vault key, and the zero image
digest. The example selects Vault Transit for all publisher proof keys. The
separate access-token key remains in each identity Secret because the current
ANP verifier still consumes a PEM JWT key.

Render without `--allow-example`; strict mode rejects reserved example domains
and mutable image tags:

```powershell
python scripts\render_kubernetes.py `
  --config C:\agent-web\production.json `
  --output C:\agent-web\rendered.json

kubectl --context agent-web-production apply -f C:\agent-web\rendered.json
```

The output includes the namespace, three service accounts, three PVCs, three
Deployments, three internal Services, and six NetworkPolicies. It does not
include Secrets, a Vault installation, certificate issuance, or public ingress.
Create those through the operator's secret manager and ingress controller. The
Services expose internal TCP/443 and expect a TLS-passthrough gateway; terminating
TLS before the publishers changes the authenticated origin and is unsupported.

## Execute the live cluster gate

After rollout, collect workload and CNI evidence:

```powershell
python scripts\kubernetes_live_gate.py `
  --config C:\agent-web\production.json `
  --context agent-web-production `
  --execute-network-probes `
  --output C:\agent-web\evidence\kubernetes.json
```

The gate verifies observed single-replica rollouts, actual runtime image IDs,
Ready pods, Bound `ReadWriteOncePod` claims, ready EndpointSlices, and the exact
NetworkPolicy set. With `--execute-network-probes`, it temporarily creates three
restricted Jobs and proves that Forecast can reach the selected public HTTPS
upstream, Forecast cannot reach the private Kubernetes API address, and an
unselected Moltbook pod cannot reach the public upstream. Probe Jobs are deleted
in a `finally` path. Review the generated evidence before accepting the cluster.

Standard NetworkPolicy is address-based, not DNS-name-based. Application-level
DNS pinning and public-address validation remain required. Operators needing a
named upstream allowlist should add their CNI's authenticated FQDN policy and
test rebinding and failover behavior.

Vault-backed mode permits publisher pods to reach only TCP/8200 on pods labelled
`app.kubernetes.io/component=vault` in a namespace labelled
`agent-web.io/key-management=true`. External Vault or cloud KMS endpoints need
an operator-specific egress rule; do not broaden the public rule to private
networks merely to reach a control plane.
