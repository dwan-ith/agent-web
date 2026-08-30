# Agent Web: Critical Analysis and Remediation Record

Status: engineering review of the full repository, August 2026.
Companion to `docs/threat-model.md`; findings there are not repeated unless
this review changed them.

This document records a deep review of the whole project — specifications,
protocol design, publishers, registry, browsers, server toolkit, deployment
contract, and tests — and what was done about every finding. Each finding is
marked **FIXED** (remediated in this pass with tests), **MITIGATED**
(reduced or bounded, residual risk documented), or **OPEN** (accepted for
now, with the reason and the path forward).

## What the project gets right

Worth stating plainly, because it constrains what "better" means:

- The trust model is coherent and small: the HTTPS origin is the trust root;
  discovery authorizes exact assertion keys; resources carry W3C
  `eddsa-jcs-2022` proofs; `@id` = canonical URL = transport URL; expiry is
  enforced. Verification fails closed at every layer reviewed.
- The authenticated-action profile (RFC 9421 strict subset + RFC 9530 digest +
  durable one-time nonces + separate authorization) is unusually disciplined,
  and the nonce replay store is genuinely shared state, not per-process memory.
- The network boundary (DNS-pinned connections resolved once and pinned for
  the connection, no redirects, byte/time caps everywhere) eliminates the
  classic SSRF/DNS-rebinding class rather than merely discouraging it.
- Conformance is enforced by committed cross-language vectors, not by shared
  code. This is the right interoperability boundary.

The weaknesses below are therefore mostly about *ecosystem completeness*,
*durability under scale and multiprocess operation*, and a set of concrete
bugs that had accumulated between modules.

## A. Fundamental limitations (strategic; OPEN by nature)

These cannot be fixed by editing this repository alone. They are the honest
boundaries of the current vision.

1. **Unregistered identifiers.** `application/agent-web+json`,
   `application/agent-web-discovery+json`, and `/.well-known/agent-web` are
   unregistered. Until IANA registration (or an RFC-quality spec publication)
   exists, independent implementations may collide with other uses. The
   profile says "registration is pursued"; it must actually be pursued before
   any third-party adoption.
2. **Origin-rooted trust has no continuity mechanism.** Whoever controls the
   origin at verification time controls the assertion keys. Web-native
   discovery has no key-history/rollback protection: a compromised origin can
   rotate keys silently and re-sign history. WNS binding generations solve
   this for the optional ANP path only. Mitigation today: clients re-fetch and
   re-verify live, so nothing is trusted from cache without expiry — but a
   future "verified snapshot" ecosystem would need discovery-level key
   history first.
3. **No revocation beyond expiry.** A leaked assertion key is valid until the
   publisher rotates discovery keys; already-distributed documents stay valid
   until their `expiresAt`. Short expiries are the operational answer, and the
   profile now explicitly recommends setting them (see B12), but there is no
   push revocation.
4. **Search/relevance is embryonic.** Registry ranking is lexical scoring over
   LIKE scans. There is no crawler scheduling, no abuse reputation, no recall
   story beyond federated hint feeds. This is the single biggest gap between
   the "sibling of the WWW" vision and the implementation.
5. **No event/subscription delivery, capability delegation, receipts, or
   dispute semantics.** Correctly deferred in the roadmap (commerce blocked on
   them), but they are prerequisites for the "agents act on services" half of
   the vision, not optional extras.
6. **Single-implementation conformance.** Python and TypeScript are twins with
   shared vectors, but no independent third party has ever interoped. The
   conformance fixtures make such an attempt cheap; it should be sought
   deliberately.
7. **SQLite-centric durability.** Every store is SQLite behind one process
   lock. This is excellent for reference deployments and hostile to horizontal
   scale. The multi-worker caveats in section D are symptoms of this choice.

## B. Security and correctness findings

| # | Finding | Where | Status |
|---|---------|-------|--------|
| B1 | Moltbook mutation rate limiter counted **all** audit rows per actor, so thread creations consumed the reply budget and vice versa; the documented 30/60 budgets were fiction | `moltbook_site/store.py` | **FIXED**: one bucket per `(actor, action)`; regression test proves independence |
| B2 | Moltbook content DB lacked WAL while sibling stores had it — inconsistent concurrency behavior in the flagship dual-projection site | `moltbook_site/store.py` | **FIXED**: WAL + `synchronous=NORMAL` |
| B3 | 48-bit content IDs (`uuid4().hex[:12]`) surfaced raw `IntegrityError` → HTTP 500 on collision | `moltbook_site/store.py` | **FIXED**: full 128-bit hex IDs |
| B4 | **Feed-generation churn defeated incremental federation**: every accepted snapshot bumped the generation even when content was identical, so peers' generation-based skip could never fire, while a comment asserted the opposite | `registry_site/store.py` | **FIXED**: content-addressed snapshots (schema v3 migration); generation advances iff verified content changes; migration test added; federation profile updated |
| B5 | Registry search truncated candidates (`LIMIT 500`, scan order) *before* relevance ranking → arbitrary, unstable results once corpus exceeded the cap | `registry_site/store.py` | **FIXED**: deterministic `ORDER BY resource_url` scan over a documented bounded candidate set (2000), scored fully before truncation |
| B6 | Registry HTML search (`/directory`) bypassed the only rate-limit rule (matched the JSON endpoint exactly) | `registry_site/app.py` | **FIXED**: both surfaces share the rule |
| B7 | **Action-result verification gap in `WebAgentBrowser.invoke`**: response `@id` origin was unbound from the action URL, and a result served by a second allowed origin was verified against the *advertising* site's discovery instead of the serving origin's own | `libagentweb/web_browser.py` | **FIXED**: result `@id` MUST use the serving origin; same-origin results verify against the browser's discovery; cross-origin results verify against that origin's fetched-and-cached discovery. Profile codified in `resource-profile.md` ("Action results"); three new tests |
| B8 | **Forecast provenance over-attestation**: stale cached records were re-signed with a fresh `retrievedAt`, making the signature attest a retrieval that never happened (the original time survived only under an extension field nothing validated) | `forecast_site/provider.py` | **FIXED**: `retrievedAt` preserved exactly; `stale` + `reverifiedAt` carry the re-attestation; HTML view shows provider + staleness; test updated |
| B9 | Forecast used one global asyncio lock: a slow upstream fetch for one location head-of-line-blocked all others | `forecast_site/provider.py` | **FIXED**: per-slug locks |
| B10 | Native-knowledge annotation POST had authentication+authorization but **no rate limit**, unlike every other mutating surface | `native_knowledge_site/app.py` | **FIXED**: per-controller sliding-window limiter (30/min default), applied after verification, keyed on the verified controller — never caller-supplied data alone |
| B11 | Native-knowledge accepted any topic slug server-side (pattern existed only in the advertised schema); collection silently truncated at 100 annotations while publishing the true total | `native_knowledge_site/store.py`, `app.py` | **FIXED**: slug pattern enforced in the store; annotations moved to a bounded paginated collection with `next`/`prev` links; index stays bounded |
| B12 | No freshness guidance tied proof validity to content volatility; unexpired-forever documents were conforming | `resource-profile.md` | **FIXED (spec)**: publishers SHOULD set `expiresAt` on volatile content; `proof.created` explicitly is not an expiry |
| B13 | Native-knowledge middleware hand-rolled security headers and lacked `Permissions-Policy` (drift from the shared installer) | `native_knowledge_site/app.py` | **FIXED**: header completed |
| B14 | **TypeScript consumers could not verify resource proofs** — validation was structural, so a forged but well-formed document passed in TS while Python rejected it | `libagentweb/typescript` | **FIXED**: full `eddsa-jcs-2022` verifier with an in-tree RFC 8785 JCS canonicalizer (`typescript/src/signing.ts`); committed cross-language vectors generated by `scripts/generate_data_integrity_vectors.py` and consumed by both language suites (9 negatives each) |
| B15 | Two pre-existing red TypeScript tests masked regressions: the redirect mock drifted from undici behavior, and one fixture carried an empty `proof` object against a schema that requires proof fields | `typescript/tests/bounded-fetch.test.ts` | **FIXED**: mocks repaired to their stated intent |
| B16 | Graphical-browser daemon API was entirely unauthenticated on loopback: any local process could navigate, expand the origin policy, and invoke actions with the custodial signing key ("private key never enters JavaScript" protected JS, not other processes) | `agent_web_browser/daemon.py` | **FIXED**: startup-generated session token required on `/api/*` and the UI entry (constant-time compare); token injected into the served index via meta tag; React client sends it; CLI prints the tokenized launch URL |
| B17 | Line-mode browser exposed no traversal bounds at the CLI level | `agent_web_line/cli.py` | **FIXED**: `--max-resources` and `--timeout` flags with validation |

## C. Protocol/spec rigor gaps closed

- **Pagination is now part of the profile.** Bounded collections with
  `next`/`prev` pages were implicit (`next` existed as a relation) but no
  publisher obeyed the spirit of invariant 6 ("bounded traversal") server-side:
  Moltbook embedded every thread inline; native-knowledge truncated silently.
  Both now paginate; the contract is written down in `resource-profile.md`.
- **Incremental federation convergence actually works now** (B4): a stable
  signed generation means unchanged content, which is precisely what the
  receiver's skip logic assumed. The federation profile states the generation
  contract normatively.

## D. Known limitations deliberately left OPEN

Recorded so the next pass starts here instead of rediscovering them.

1. **Per-process maintenance drain** (`agent_web_server/maintenance.py`):
   `/ops/maintenance/enter` quiesces only the worker that receives the request.
   With `--workers > 1`, the coordinated backup contract degrades silently.
   Current deploy guidance runs writers single-worker; the durable fix is a
   file-backed drain gate (the nonce-store pattern) and it is the top-priority
   open item.
2. **Unbounded forensic tables**: `authorization_audit` and Moltbook's
   `audit_log` grow forever. Need operator-configured pruning/rotation with an
   export hook.
3. **Registry lifecycle**: no re-verification scheduler or eviction (expired
   entries filter out of queries but linger in storage); the indexer aborts a
   whole site past its resource bound instead of indexing-with-truncation-flag;
   federation verifies sources sequentially (hours-scale worst case at the
   configured bounds); `RegistryIndexer.index` calls `asyncio.run`, so it
   cannot run inside a live loop.
4. **Rate limiter edge**: under sustained distinct-key pressure the limiter
   sheds *new* keys, which can lock out legitimate newcomers while tracked
   abusers keep slots; `client_ip_key` is wrong behind proxies (documented;
   operators must supply a trusted key function).
5. **Observability**: readiness runs `PRAGMA quick_check` synchronously inside
   the async handler — can stall serving for seconds on large databases.
6. **Key custody on Windows**: `chmod 0o600` is a near-no-op on NTFS where
   this repository is developed; native-knowledge's CLI loads its PEM with no
   restriction helper at all. `docs/key-custody.md` should gain platform-
   specific ACL guidance (e.g., `icacls` inheritance disablement).
7. **Minor hardening debt**: `secrets.py` stat-then-read TOCTOU (4 KiB cap
   bounds the blast radius); JSON-RPC batch requests are blanket-rejected even
   when unrelated methods are unaffected; authorization errors return as HTTP
   200 envelopes (defensible JSON-RPC style, easy to mishandle).
8. **Graphical browser UX limits**: the action form builder supports flat
   string/number/boolean schemas only; session history is unbounded in
   memory; App.tsx has zero component tests (only the API client is tested).
9. **No static analysis gate**: ruff/mypy are absent from `verify.py`. For a
   codebase whose security argument depends on subtle parsing and ordering,
   type checking would be cheap insurance.

## E. Verification performed for this pass

- All touched packages green: libagentweb 44 Python tests (+3 vector tests),
  moltbook 6 (+1), forecast 6, native-knowledge 10 (+3), registry 22 (+2),
  line-mode 4, daemon 8 (+1).
- TypeScript suite green including 13 new Data Integrity tests consuming the
  same committed vectors as Python.
- New vectors committed under `libagentweb/conformance/data-integrity/` and
  mirrored into the TypeScript package; regeneration is deterministic
  (fixed RFC 8032 test seed, fixed timestamps).

## F. Recommended order of next work

1. Durable cross-process maintenance drain gate (D1).
2. Audit-log pruning/rotation with export (D2).
3. Registry scheduler + truncation-tolerant indexer + concurrent source
   verification (D3).
4. Static-analysis gate in `verify.py` (D9).
5. Platform-correct key custody documentation and helpers (D6).
6. Begin IANA registration drafts and solicit one independent implementation
   against the committed vectors (A1, A6).

## G. Iteration 2: demo-readiness pass (same day)

A second pass drove the project to live-demo quality. Outcomes:

- **The demo path itself was completed.** `scripts/demo_network.py` now also
  starts the native Agent Web publisher, provisions the graphical browser's
  Web-native caller identity (`build_caller_controller` over the browser
  key), registers that controller as a trusted annotation writer, and indexes
  the native site into the registry through Web-native discovery. The proof
  report gained a `webNativeAnnotation` section; a live run shows the daemon
  signing an RFC 9421 request, the publisher verifying it, and the daemon
  re-verifying the signed result (`verifiedByDaemon: true`). The demo can now
  show every layer — discovery, navigation, authenticated machine-native
  write, registry indexing, TypeScript validation — in one command.
- **Served-UI verification against the running daemon**: unauthenticated UI
  entry → 401; tokenized entry → 200 with the injected session-token meta and
  the freshly built bundle; the bundle carries the header logic; then the UI's
  exact API sequence (status → connect → search action → authenticated
  annotation) all succeeded. Pixel-level clicking could not be automated in
  this environment (the in-app browser webview never attached), so this
  HTTP-level proof stands in; a human demo clicks through what these checks
  prove boots.
- **Fixed while re-verifying**: readiness integrity probes moved off the
  event loop in native-knowledge (the server toolkit already used
  `asyncio.to_thread`); an off-by-one in audit retention pruning deleted one
  record past the window in both the authorization store and Moltbook's audit
  log (kept N−1 instead of N); the trusted-proxy rate-limit key
  (`proxied_client_key`) implements standard rightmost-trusted-hop semantics
  with tests; the registry crawl now truncates-with-flag instead of
  discarding a whole site past its bound, expired entries are swept with a
  feed-generation advance, federation verifies sources concurrently (bounded
  semaphore of four), the line-mode CLI exposes traversal bounds, the React
  history buffer is capped, and Windows key-custody ACL guidance was added to
  `docs/key-custody.md`.
- One flow subtlety confirmed correct by testing: invoking an advertised
  action while the browser's current resource does not advertise it fails
  cleanly (HTTP 400), which is the profile's invoke rule working as designed.

Remaining open items are unchanged from section D except D2 (done for both
stores), D3 (truncation, sweep, and concurrency done; operator scheduling
still open), D5 (done), and D6 (documented; helper still best-effort).
