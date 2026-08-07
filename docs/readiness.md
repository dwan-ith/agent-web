# Agent Web readiness

Assessment date: 2026-08-06.

## Result

- Secure local-reference milestone: **100%**
- Public, secure, multi-operator Agent Web: **74%**
- Baseline before this production-beta hardening pass: approximately **43%**

The 74% number is an acceptance-gate score, not a code-volume estimate. A point
is awarded only when there is implementation and proportionate evidence.

| Gate | Weight | Earned | Current evidence | Remaining acceptance work |
|---|---:|---:|---|---|
| Protocol and cross-language conformance | 12 | 11 | Resource Profile 0.2, JSON Schema/JSON-LD, Python and TypeScript validation, typed traversal | External implementations and media-type/standards process |
| Identity, transport, and proof security | 14 | 13 | DID-WBA `e1_`, TLS, HTTP Message Signatures, nonces, content digests, signed AD/resources, WNS 1.1 exact handles with rollback floors, Vault Transit Ed25519 signer boundary with local signature verification | Live managed/HSM custody attestation, external audit, production TLS/WNS evidence |
| Authorization and abuse controls | 12 | 9 | Default-deny mutation grants, exact DID/action/scope, expiry, max uses, revocation, audit, application rate limits | Delegation/capability exchange, distributed quotas, operator trust policy and abuse response |
| Publishers and bridges | 10 | 9 | Durable Moltbook plus real bounded Open-Meteo bridge, shared human/machine state | More independent site implementations and production upstream SLOs |
| Agent browsers | 9 | 8 | Line-mode and graphical browsers, loopback key custody, proof/origin/network policy, confirmation, live actions | Packaged end-user distribution, accessibility/usability and third-party client compatibility |
| Registry and search | 10 | 9 | Offline admission, live proof verification, atomic indexing, bounded crawl, original proof/DID/JCS digest retained, DNS-policy-to-connection pinning, default-deny Kubernetes egress contract | Distributed crawl scheduling, ranking/abuse policy, live CNI enforcement evidence |
| Packaging and deployment | 10 | 6 | Seven wheels, version-pinned image inputs, hardened publisher and observability Compose contracts, Vault override, four separate live OS processes | Execute containers on a Docker host, image digests/SBOM/hash-locked supply chain, production ingress |
| Operations and resilience | 10 | 8 | SQLite-backed readiness, private low-cardinality metrics, structured request logs, six alert rules, authenticated replica write draining, coordinated verified backups, non-overwriting restore, incident/threat/DR runbooks | Deployed alert delivery, active-passive/transactional HA, encrypted off-site restore drills and achieved RPO/RTO |
| Genuine public multi-operator federation | 8 | 1 | Separate processes, identities, origins, state, and offline registry operator path | Real domains and certificates controlled by at least two unrelated operators |
| Independent conformance/security validation | 5 | 0 | No claim | Third-party implementation, penetration test, protocol interop event |
| **Total** | **100** | **74** |  |  |

## Evidence run

The completed gate demonstrated:

- 59 passing Python tests;
- 8 passing TypeScript/React tests;
- a clean Python dependency check;
- a successful React production build;
- `npm audit` reporting zero vulnerabilities;
- seven successfully built wheels containing the server authorization and
  lifecycle modules, Registry package, and compiled graphical assets;
- a four-origin in-process TLS network with real Open-Meteo data, authenticated
  granted mutation, proof-preserving Registry search, TypeScript validation,
  and graphical browser connection;
- a second federation with four distinct operating-system PIDs and separate
  identity manifests/state directories;
- static validation of the non-root, read-only, capability-dropped publisher,
  observability, Vault-managed-signing, NetworkPolicy, public-beta-manifest,
  and external-review-bundle contracts.

Docker is not installed on the verification machine. Therefore the Compose
artifacts are **not** counted as a successful container deployment.

## Highest-risk open gaps

1. Vault Transit signing is implemented for publisher proofs and browser HTTP
   signatures, but no live Vault/HSM/KMS instance or custody attestation was
   available. The ANP verifier still uses a separate PEM access-token key.
2. WNS publication, exact reverse verification, generation floors, and rotation
   are implemented locally, but no Handle is yet operated on public DNS/TLS.
3. NetworkPolicy default-deny and bounded egress manifests validate statically,
   but no CNI executed the required allowed-public/denied-private probes.
4. Every enumerated HTTP replica can now be drained before a sequential verified
   snapshot, with release attempted on all failure paths. Omitted replicas,
   offline writers, active-active storage, off-site recovery, and multi-region
   failover remain operator responsibilities and are not proven here.
5. All live origins in acceptance are controlled by this repository on one
   machine. This is process federation, not independent governance.
6. A public federation gate and deterministic review bundle now exist, but no
   external team has audited the cryptography integration, implemented the
   profile independently, or run adversarial public interoperability tests.

## Next acceptance milestone

The next honest milestone is a two-operator public beta:

1. deploy Moltbook and Registry under one operator and Forecast under another;
2. use public DNS and CA-issued TLS, separate managed key custody, and operate
   the implemented WNS handles;
3. execute the implemented key, rotation, multi-replica recovery, alert, and
   public-federation gates across operators and preserve their evidence;
4. prove the checked egress policy on a NetworkPolicy-capable CNI;
5. connect monitoring to a staffed receiver and complete an off-site restore;
6. have a third party run the conformance suite and a focused security review.

Only after those checks pass should readiness move materially above 74%.
