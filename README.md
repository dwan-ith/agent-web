# Agent Web

**Agent Web** is an experimental implementation of a distinct, open,
machine-native Web ecosystem running on the same Internet as the World Wide
Web. Agents publish, discover, navigate, verify, and act on interconnected
resources and services through agent browsers. Agent Web can project existing
systems through bridges, but it does not depend on human websites, HTML, or an
agent-only protocol stack.

```text
Internet - IP, DNS, TLS, TCP/QUIC
    |
    +-- World Wide Web - human sites, HTML, Web browsers
    |
    +-- Agent Web - agent-native sites, typed resources, actions,
                    discovery, trust, search, and agent browsers
```

The name refers to the whole ecosystem, not one JSON format. This repository
keeps three levels separate:

1. **Agent Web** - the ecosystem analogous to the World Wide Web.
2. **Agent Web Protocol/Profile** - portable rules for resources, discovery,
   typed navigation, proofs, and action affordances.
3. **Implementations** - native sites, dual-projection sites, bridges, agent
   browsers, registries, and search/indexing services.

## The Architecture

The World Wide Web and Agent Web are sibling application ecosystems. They may
share HTTPS, origins, URLs, databases, and canonical state, but they have
different clients, navigation semantics, publishing contracts, and discovery
graphs. An Agent Web site may be native, dual-projection, or bridged. The
following diagram is the dual-projection topology, not the definition of the
whole Agent Web:

```text
             CANONICAL SYSTEM OR EXISTING API
                       │
          ┌────────────┴────────────┐
          │                         │
   Human representation     Agent Web representation
      HTML / apps          signed JSON / typed links /
          │                affordances / provenance
        humans                       │
                                   agents

   A bridge is used only where the canonical system cannot publish the
   Agent Web representation itself.
```

In the dual-projection topology, a resource can expose HTML to a human and an
Agent Web resource to an agent from the same authority. Native Agent Web sites
do not need an HTML representation. Bridged sites publish explicitly derived,
attributable snapshots of an upstream authority. None of these topologies
requires a new transport network.

**The Bridge** is the compatibility mechanism for systems that cannot publish Agent Web representations directly. It transforms a bounded upstream response into structured JSON, typed links, actions, and provenance without pretending to become the upstream authority. First-party bridges may offer audited write-through actions; third-party bridges must expose source, retrieval, transformation, and freshness boundaries. New machine-native sites do not need a bridge.

Agent Web is not a new transport network. Reusing HTTP does not reduce it to an
API layer for the WWW: its separation comes from its independent resource graph,
agent-native sites, generic clients, discovery, trust, publishing model, and
search ecosystem.

## Independence from agent-only protocol stacks

Agent Web deliberately disagrees with a future in which an agent-only Internet and a growing mandatory family of agent protocols displaces the human Web. The Agent Web core therefore depends on ordinary HTTPS, standard HTTP semantics, JSON, typed Web links, and W3C Data Integrity proofs. A conforming publisher or browser does not need ANP.

ANP (Agent Network Protocol) is retained as an optional compatibility binding for deployments that want DID-WBA, WNS, Agent Descriptions, or ANP JSON-RPC. It cannot define the Agent Web resource model, discovery root, addressing, or default action transport.

```text
        Agent Web resources, links, and affordances
                         │
              HTTP representation semantics
                         │
                  HTTPS / Web origins
                         │
                 DNS / TLS / TCP / QUIC / IP

Optional adapters: ANP, MCP, A2A, or future protocols
```

Web-native discovery lives at `/.well-known/agent-web`. It binds the HTTPS origin, entry resource, representation profile, and authorized proof keys. The reference publishers still expose their older ANP endpoints for interoperability, but the new `WebAgentBrowser` can discover and cryptographically verify their resources without using ANP discovery or an ANP client.

## Repository map

| Early World Wide Web component | Agent Web component |
|---|---|
| `libwww` | `libagentweb` Python and TypeScript packages |
| `httpd` | `agent-web-server` publishing, identity, authorization, and TLS toolkit |
| NeXT browser/editor | React browser plus a loopback identity daemon |
| line-mode browser | `line-mode-agent-browser` |
| first HTML site | Moltbook, Forecast, and Registry publishers |
| first native agent-only site | Native Knowledge publisher |

- `libagentweb/`: Resource Profile 0.2, JSON Schema, JSON-LD context,
  ANP-free Web discovery and proof-verifying browser, optional ANP adapter,
  TypeScript consumer, and conformance fixtures.
- `agent-web-server/`: Web-native discovery, DID hosting, optional WNS handle
  publication, signing, HTTP
  security, persistent replay protection, scoped authorization grants,
  identity lifecycle, and verified backup/restore tooling.
- `sites/moltbook/`: SQLite-backed discussions with one canonical store for
  the Agent Web resource and human forum projection.
- `sites/native-knowledge/`: persistent agent-only knowledge graph with no HTML
  projection and no ANP dependency.
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

The protocol-neutral reference implementation provides:

- origin-bound `/.well-known/agent-web` discovery over HTTPS;
- Web-native resource verification using discovery-authorized Multikey or JWK
  keys, with no ANP runtime required;
- ordinary HTTP as the default action binding and ANP/MCP/A2A as optional
  interfaces;
- authenticated HTTP mutations using a strict RFC 9421 Ed25519 profile, RFC
  9530 body digests, HTTPS caller controllers, short lifetimes, and durable
  one-use nonces, without ANP or DID-WBA;
- signed non-transitive registry federation feeds whose receiving registries
  independently re-fetch and verify every original Agent Web publisher;
- W3C `eddsa-jcs-2022` Data Integrity proofs implemented in `libagentweb`
  rather than delegated to an agent-network SDK;

The optional ANP compatibility deployment additionally provides:

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

The gate runs the complete Python and TypeScript/React suites, source
compilation, dependency integrity,
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

Build all eight Python distribution artifacts:

```powershell
.\.venv\Scripts\python.exe -m pip wheel --no-deps --no-build-isolation `
  --wheel-dir dist `
  libagentweb\python agent-web-server\python `
  sites\moltbook\python sites\forecast\python sites\registry\python `
  sites\native-knowledge\python `
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
agent-web-registry-federate --help
```

For the isolated container contract, see [deploy/README.md](deploy/README.md).
