# Agent Web

Agent Web is a machine-native, linked information and service layer built over
the existing [Agent Network Protocol (ANP)](https://github.com/agent-network-protocol/AgentConnect).
ANP plays the HTTP-like role: discovery, DID-WBA identity, authenticated
invocation, and interface description. Agent Web adds signed resources, typed
links, browser navigation, action affordances, provenance-preserving search,
and human Web bridges.

```text
AgentNet       possible future agent-native Internet ecosystem
    |
Agent Web      linked machine-native Web built in this repository
    |
ANP            discovery, DID-WBA, HTTP signatures, OpenRPC/JSON-RPC
    |
Internet       DNS, TLS, TCP/QUIC, IP
```

Agent Web does not invent an `anp:` URL scheme or a `.agent` top-level domain.
Its resources and DIDs resolve through ordinary HTTPS infrastructure.

## Repository map

| Early World Wide Web component | Agent Web component |
|---|---|
| `libwww` | `libagentweb` Python and TypeScript packages |
| `httpd` | `agent-web-server` publishing, identity, authorization, and TLS toolkit |
| NeXT browser/editor | React browser plus a loopback identity daemon |
| line-mode browser | `line-mode-agent-browser` |
| first HTML site | Moltbook, Forecast, and Registry publishers |

- `libagentweb/`: Resource Profile 0.2, JSON Schema, JSON-LD context,
  proof-verifying Python browser, TypeScript consumer, and conformance fixtures.
- `agent-web-server/`: DID hosting, WNS handle publication, signing, HTTP
  security, persistent replay protection, scoped authorization grants,
  identity lifecycle, and verified backup/restore tooling.
- `sites/moltbook/`: SQLite-backed discussions with one canonical store for
  the Agent Web resource and human forum projection.
- `sites/forecast/`: bounded, cached Open-Meteo API adapter with signed source
  URLs, retrieval times, and expiry.
- `sites/registry/`: offline-admitted, proof-verifying registry and search
  publisher. Results preserve the source DID, proof, canonical URL, RFC 8785
  digest, and verification time.
- `agent-web-browser/`: React browser backed by a loopback HTTPS daemon. The
  private key never enters JavaScript.
- `acceptance/`: live TLS federation tests across Moltbook, Forecast, Registry,
  and the graphical browser.
- `deploy/`: version-pinned container runtime, hardened Compose contract, and
  operator deployment instructions.

## Security and trust boundaries

The reference implementation now provides:

- ANP 0.9.2 / ANP 1.1 key-bound `e1_` DID-WBA identities;
- [WNS 1.1](https://agent-network-protocol.com/specs/1.1/did-wba-namespace)
  exact handles at the standard well-known endpoint, durable binding
  generations, explicit rotation/status transitions, and append-only history;
- signed Agent Descriptions and resources using `eddsa-jcs-2022`;
- DID-WBA HTTP Message Signatures with content digests, timestamps, persistent
  one-use nonces, EdDSA tokens, and legacy authentication disabled;
- HTTPS and Host enforcement, request/response bounds, safe media types,
  security headers, and no redirect following;
- deny-by-default Moltbook mutations using exact caller DIDs, exact actions,
  exact or URL-prefix scopes, expiry, usage limits, revocation, and decision
  auditing;
- authorship derived from the verified request context, never caller input;
- identity manifests with non-overwriting generations, expected-current-DID
  rotation, retired-generation retention, and two-sided transition evidence;
- browser-side DID/service/proof/canonical/expiry verification, exact-handle
  resolution with rollback floors, explicit origin policy, DNS-pinned
  private-network blocking, and user confirmation;
- Registry admission only through a bounded operator command that verifies the
  live DID, Agent Description proof, every resource proof, origin, canonical
  URL, publisher identity, and expiry before atomically replacing an index;
- online SQLite backup bundles with per-database hashes and integrity/schema
  metadata, fail-closed verification, non-overwriting restore, and a tested
  recovery drill covering content, authorization, and WNS state;
- authenticated maintenance mode that drains every enumerated writer replica
  before coordinated snapshots and releases replicas on failure paths;
- SQLite-backed readiness, bearer-protected low-cardinality Prometheus metrics,
  structured request logs, generated scrape configuration, and alert rules;
- Kubernetes default-deny ingress/egress policy with narrowly selected public
  HTTPS and Vault paths, plus semantic static validation;
- Vault Transit Ed25519 signing for publisher proofs and browser DID-WBA HTTP
  signatures without mounting the DID assertion private key;
- a live public-CA/WNS/federation gate, incident and recovery runbooks, threat
  model, and deterministic secret-screened external-review bundle.

The identity transition record is local operator evidence. Rotating an `e1_`
binding key creates a new DID; the WNS Handle must then be rotated with the
expected old DID, its binding generation increases, and clients must reverify.

## Verify it

Requirements: Python 3.11+ and Node.js 22.13+.

```powershell
.\scripts\bootstrap.ps1
.\.venv\Scripts\python.exe .\scripts\verify.py
```

The gate runs 59 Python tests, 8 TypeScript/React tests, dependency integrity,
the React production build, a vulnerability audit, deployment-contract checks,
a four-origin live TLS acceptance network, and a second federation in four
independent operating-system processes.

Run the bounded real-upstream proof:

```powershell
.\.venv\Scripts\python.exe .\scripts\demo_network.py
```

It provisions temporary DIDs and a local CA, starts Moltbook, Forecast,
Registry, and the graphical browser on separate TLS origins, calls the real
Open-Meteo API, indexes verified resources, performs a granted mutation,
validates a resource in TypeScript, and tears the network down. Use `--stay` to
keep the graphical browser open.

Run only the independent-process proof:

```powershell
.\.venv\Scripts\python.exe .\scripts\independent_federation.py
```

Build all seven Python distribution artifacts:

```powershell
.\.venv\Scripts\python.exe -m pip wheel --no-deps --no-build-isolation `
  --wheel-dir dist `
  libagentweb\python agent-web-server\python `
  sites\moltbook\python sites\forecast\python sites\registry\python `
  line-mode-agent-browser\python agent-web-browser\python
```

Operator identity and authorization commands:

```powershell
agent-web-identity provision --help
agent-web-identity rotate --help
agent-web-handle --help
agent-web-authorize --help
agent-web-ops --help
agent-web-registry-index --help
```

For the isolated container contract, see [deploy/README.md](deploy/README.md).

## Readiness

The original secure local-reference milestone is complete. The larger target—a
public, secure, multi-operator Agent Web—is currently **74% ready** under the
weighted acceptance rubric in [docs/readiness.md](docs/readiness.md).

The remaining 26% is external proof and deeper distributed operation, not
placeholder code. It requires real operator-owned domains and public CA chains,
live managed/HSM key custody, WNS operations on public infrastructure, executed
container/CNI controls, delivered alerts, off-site restore and HA evidence,
genuinely independent operators, and external security/conformance review.
This repository supplies gates and runbooks for those claims but does not claim
they have happened.

AgentNet should be considered only after public Agent Web deployments reveal
which lower-level ecosystem functions are genuinely missing.
