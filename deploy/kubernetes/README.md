# Kubernetes network boundary

`network-policies.json` is a Kubernetes `List` containing additive NetworkPolicy resources. It denies ingress and egress for Agent Web publisher pods by default, admits only gateway ingress, and grants DNS to all publishers. Only the Forecast adapter and the separately labelled Registry indexer receive public TCP/443 egress; private, loopback, link-local, documentation, benchmark, multicast, and reserved IPv4/IPv6 ranges are excluded.

The cluster must use a CNI that enforces `networking.k8s.io/v1` NetworkPolicy. Before applying the policies, label publisher pods with `app.kubernetes.io/part-of=agent-web`, label individual workloads with `app.kubernetes.io/component=forecast` or `registry-indexer`, and label the ingress namespace and gateway pod exactly as described in the policy. Validate the effective policy with denied-private and allowed-public probes in the target cluster: manifest validation alone cannot prove CNI enforcement.

Standard NetworkPolicy is address-based, not DNS-name-based. Application-level DNS pinning and public-address validation therefore remain required even with this layer. Operators that need an allowlist limited to named upstreams should add their CNI's authenticated FQDN policy and test DNS rebinding and failover behavior.

Vault-backed mode also permits publisher pods to reach only TCP/8200 on pods labelled `app.kubernetes.io/component=vault` in a namespace labelled `agent-web.io/key-management=true`. External Vault or cloud KMS endpoints require an operator-specific egress rule; do not broaden the checked public rule to private networks just to make a control-plane endpoint reachable.
