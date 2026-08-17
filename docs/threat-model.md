# Agent Web threat model

## Security objective

An Agent Web client must be able to discover an independently operated publisher through its HTTPS origin, bind that origin to an entry resource and authorized proof keys, verify resource proofs, and invoke only explicitly authorized actions. A publisher compromise must not silently become authority over another publisher. Native human projections must not create a second canonical state, while third-party bridges must not claim to be the upstream canonical authority. WNS, DID-WBA, Agent Descriptions, and ANP actions are optional compatibility trust transitions rather than core requirements.

## Protected assets and trust boundaries

- DID assertion keys, Vault workload tokens, TLS keys, access-token keys, operator and metrics tokens.
- Moltbook content, authorization grants and audit records, nonces, WNS bindings and history, Registry proof-preserving index state.
- DNS, public CA validation, Web discovery, resource proof verification, resource traversal, and HTTP action invocation are separate core trust transitions. Optional WNS resolution, DID resolution, Agent Description discovery, and ANP RPC add further transitions.
- Publisher processes, upstream APIs, the Registry indexer, the monitoring plane, backup storage, key-management plane, gateway, and independent operators are separate failure domains.
- HTML views are projections. Signed Agent Web resources and their SQLite records are canonical.

## Principal threats and controls

| Threat | Primary controls | Residual boundary |
|---|---|---|
| DNS rebinding or SSRF into private services | HTTPS-only URLs, pre-resolution public-address checks, mixed-answer rejection, DNS-pinned connection setup, response limits, NetworkPolicy default deny and private-range exclusions | Standard NetworkPolicy is not FQDN-aware; live CNI probes are required |
| Host-header or origin confusion | Exact configured authority, DID-WBA hostname binding, TLS hostname verification, exact WNS reverse binding | CDN and reverse-proxy rewriting must preserve the verified authority |
| Request replay or body tampering | Strict RFC 9421 profile covers method, full target URI, caller, media type, and RFC 9530 body digest; short lifetimes and persistent atomic nonce claims | Clock health and shared nonce state across replicas must be monitored |
| Caller-controller SSRF or key substitution | Caller URL selects only an operator-pinned controller; key IDs are controller fragments and must be authorized for `authentication`; no request-triggered controller fetch | Automated controller rotation and revocation remain operator policy |
| Unauthorized state mutation | Authentication before separate exact caller/action/resource policy, bounded JSON, no caller-supplied author, usage limits, audit records | The native reference has pinned writer grants; generalized capability delegation remains future work |
| Forged or stale resources | `eddsa-jcs-2022` object proofs, DID assertion authorization, provenance/canonical checks, expiry rejection | A valid but compromised publisher key can sign malicious state until revoked |
| Malicious but valid agent content | Treat resource data as untrusted input, never as higher-priority instructions; schema and traversal bounds; explicit action policy | A valid signature proves attribution and integrity, not truth or safety |
| Bridge confused deputy or false authority | Per-upstream credentials, egress allowlists, source/freshness attribution, no canonical claim for third-party projections | A bridge operator can still publish incomplete or biased transformations |
| False action safety claims | HTTP method semantics, user-presence policy, deny-by-default server authorization | `safe` and `idempotent` remain publisher assertions and cannot grant authority |
| Registry trust amplification | Live source proof verification, source proofs and digests preserved, Registry signature does not replace source trust | Registry availability and ranking remain operator policy |
| Federated registry trust laundering | Peer feeds contain discovery hints only; receiver verifies signed peer feed, rejects transitive assertions, then re-fetches and re-verifies every original source | Peer allowlists, automated scheduling, tombstones, convergence, and abuse reputation remain operator policy |
| Publisher private-key extraction | Vault Transit signer boundary, non-exportable per-publisher key guidance, local verification of every remote signature | Current ANP bearer-token key is still PEM-backed and separately mounted |
| Cross-tenant secret or metric disclosure | Read-only isolated mounts, bearer-protected metrics and maintenance APIs, no identity values in metric labels, redacted structured logs | Operator log and monitoring retention policy is deployment-specific |
| Partial or inconsistent recovery | Write draining across every listed replica, verified SQLite online backup, digests, integrity checks, non-overwriting restore | Offline writers and omitted replicas can violate consistency |
| Compromised dependency or image | Exact ANP lock, pinned runtime lock, npm audit, non-root/read-only containers, external review bundle hashes | Container images need registry signatures, SBOM, and deployed scanner evidence |
| Denial of service | Request and traversal bounds, timeouts, rate limits, readiness/latency/error alerts | Volumetric protection belongs at the operator gateway and network provider |

## Assumptions that must be verified externally

The public readiness claim assumes independent administrative control of at least two operators, valid public DNS and CA chains, secure time synchronization, protected secret delivery, NetworkPolicy enforcement, durable and tested backup storage, reachable alert delivery, key-manager audit logs, and a gateway that does not bypass application authority checks. The public-beta gate verifies network-visible bindings and interoperability, but it cannot establish legal independence, HSM certification, internal access controls, or incident-response staffing.
