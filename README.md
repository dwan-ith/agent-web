# Agent Web

**Agent Web** is an experimental reference profile demonstrating a machine-native representation of the Web. Rather than proposing a clean succession to a completely new "Agent Internet", Agent Web makes existing Internet resources natively accessible and actionable to both humans and autonomous agents.

## The Architecture

The current Internet contains immense embedded value: billions of URLs, databases, APIs, identities, commerce systems, and social infrastructures. Recreating this ecosystem entirely inside an independent successor "Agent Internet" incurs enormous migration and switching costs. In contrast, Agent Web encodes a fundamental invariant enabling a significantly cheaper transition: **Human and Agent Web projections read the same canonical store.** There will be many json-native agent websites that won't have **The Bridge** but the switching cost for protocols is too high to replace all the things that exists today.

```text
                     INTERNET
                        │
                    The Bridge
                        │
             ┌──────────┴──────────┐
             │                     │
        Human Web              Agent Web
             │                     │
        HTML / apps         JSON / links /
        human actions       typed actions /
                            provenance
             │                     │
           humans                agents
```

Under this architecture, the underlying resource (e.g. `example.com/product/123`) does not disappear into a disjoint and separate agent network. Instead, it exposes two native representation layers pointing back to the same state. A normal website is a UI/HTML representation for a human; an Agent Web site provides a structured representation for an agent. 

**The Bridge** is the crucial structural mechanism making this coexistence possible. Rather than acting as a simple, bolt-on adapter, The Bridge is a first-class feature of the Agent Web invariant: it is the layer that safely and natively projects existing, canonical web state into a machine-actionable representation (via structured JSON, typed links, actions, and provenance). While entirely new, agent-exclusive platforms can operate without it, the Bridge ensures that decades of existing Internet infrastructure can be seamlessly integrated into the Agent Web without demanding a complete and costly platform migration.

Current autonomous agents—such as OpenClaw or Hermes Agents—are often forced to extract DOM representations aimed at people, relying on brittle inference to observe pages and invoke actions. The Agent Web projection (enabled by The Bridge) offers a dramatically clearer standard contract. It directly exposes what resources exist, their JSON schemas, their canonical state, authorization parameters, and interaction endpoints. 

This topology is highly analogous to the **Deep Web or Dark Web**. Agent Web is not a replacement for standard Internet infrastructure (HTTP/IP); it is an enormous, coexisting information space reached over the same underlying Internet. It provides its specialized population—autonomous machines—with native interfaces, discovery, search, and addressing conventions. 

## Relationship to the Agent Network Protocol (ANP)

While the [Agent Network Protocol (ANP)](https://github.com/agent-network-protocol/AgentConnect) describes an AI-native network positioned as a successor to today's human-centric infrastructure, Agent Web argues the future is a simultaneous parallel projection—and treats ANP as a powerful enabling technology beneath the Agent Web side of the network.

When agents interact directly with other agents or purely machine-oriented data units on the Agent Web, they can utilize ANP as their HTTP-like discovery and structural communication substrate. 

```text
               Agent Web
                   │
           machine-native APIs / actions
                   │
                  ANP (communication substrate)
                   │
          agent ↔ agent/services
```

Agent Web does not invent an `anp:` URL scheme or a `.agent` top-level domain. Its resources and DIDs resolve through the ubiquitous and ordinary HTTPS infrastructure.

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
  HTTPS and Vault paths, plus a 19-resource production renderer that enforces
  digest-only images, Restricted pods, one-writer `Recreate` rollouts,
  `ReadWriteOncePod` storage, and a live cluster/CNI evidence gate;
- Vault Transit Ed25519 signing for publisher proofs and browser DID-WBA HTTP
  signatures without mounting the DID assertion private key;
- a live public-CA/WNS/federation gate, incident and recovery runbooks, threat
  model, deterministic secret-screened external-review bundle, CycloneDX 1.7
  wheel SBOM, and explicitly unsigned SLSA-v1-format subject binding.

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
