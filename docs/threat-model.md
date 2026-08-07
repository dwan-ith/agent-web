# Agent Web threat model

## Security objective

An Agent Web client must be able to discover an independently operated publisher, bind its HTTPS origin, WNS handle, DID, Agent Description, resource proofs, and ANP actions, and invoke only explicitly authorized actions. A publisher compromise must not silently become authority over another publisher. Human Web projections must not create a second canonical state.

## Protected assets and trust boundaries

- DID assertion keys, Vault workload tokens, TLS keys, access-token keys, operator and metrics tokens.
- Moltbook content, authorization grants and audit records, nonces, WNS bindings and history, Registry proof-preserving index state.
- DNS, public CA validation, WNS resolution, DID resolution, Agent Description discovery, resource traversal, and ANP RPC are separate trust transitions.
- Publisher processes, upstream APIs, the Registry indexer, the monitoring plane, backup storage, key-management plane, gateway, and independent operators are separate failure domains.
- HTML views are projections. Signed Agent Web resources and their SQLite records are canonical.

## Principal threats and controls

| Threat | Primary controls | Residual boundary |
|---|---|---|
| DNS rebinding or SSRF into private services | HTTPS-only URLs, pre-resolution public-address checks, mixed-answer rejection, DNS-pinned connection setup, response limits, NetworkPolicy default deny and private-range exclusions | Standard NetworkPolicy is not FQDN-aware; live CNI probes are required |
| Host-header or origin confusion | Exact configured authority, DID-WBA hostname binding, TLS hostname verification, exact WNS reverse binding | CDN and reverse-proxy rewriting must preserve the verified authority |
| Request replay or body tampering | Persistent atomic nonce claims, timestamp windows, HTTP Message Signatures, content-digest verification | Clock health and shared nonce state across replicas must be monitored |
| Unauthorized state mutation | Authentication before exact subject/action/resource grants, bounded JSON, no caller-supplied author, usage limits, audit records | Operator grant issuance remains privileged and needs separation of duties |
| Forged or stale resources | `eddsa-jcs-2022` object proofs, DID assertion authorization, provenance/canonical checks, expiry rejection | A valid but compromised publisher key can sign malicious state until revoked |
| Registry trust amplification | Live source proof verification, source proofs and digests preserved, Registry signature does not replace source trust | Registry availability and ranking remain operator policy |
| Publisher private-key extraction | Vault Transit signer boundary, non-exportable per-publisher key guidance, local verification of every remote signature | Current ANP bearer-token key is still PEM-backed and separately mounted |
| Cross-tenant secret or metric disclosure | Read-only isolated mounts, bearer-protected metrics and maintenance APIs, no identity values in metric labels, redacted structured logs | Operator log and monitoring retention policy is deployment-specific |
| Partial or inconsistent recovery | Write draining across every listed replica, verified SQLite online backup, digests, integrity checks, non-overwriting restore | Offline writers and omitted replicas can violate consistency |
| Compromised dependency or image | Exact ANP lock, pinned runtime lock, npm audit, non-root/read-only containers, external review bundle hashes | Container images need registry signatures, SBOM, and deployed scanner evidence |
| Denial of service | Request and traversal bounds, timeouts, rate limits, readiness/latency/error alerts | Volumetric protection belongs at the operator gateway and network provider |

## Assumptions that must be verified externally

The public readiness claim assumes independent administrative control of at least two operators, valid public DNS and CA chains, secure time synchronization, protected secret delivery, NetworkPolicy enforcement, durable and tested backup storage, reachable alert delivery, key-manager audit logs, and a gateway that does not bypass application authority checks. The public-beta gate verifies network-visible bindings and interoperability, but it cannot establish legal independence, HSM certification, internal access controls, or incident-response staffing.
