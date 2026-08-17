# Agent Web Registry Federation 0.1

Status: implemented experimental profile, August 2026.

Registry federation exchanges discovery hints, not trust. A peer registry can
help another registry find Agent Web sites, but its signature cannot substitute
for the original publisher's HTTPS discovery, authorized key, resource proof,
canonical URL, or expiry checks.

## Discovery

A registry entry resource advertises exactly one typed link:

```json
{
  "rel": "registry-federation",
  "href": "https://registry.example/registry/resources/federation.json",
  "mediaType": "application/agent-web+json"
}
```

The feed is a normal signed Agent Web resource with types
`AgentWebCollection` and `RegistrySourceFeed`. Its source links have
`rel: source`, media type `application/agent-web-discovery+json`, and canonical
targets ending in `/.well-known/agent-web` with no query or fragment. ANP Agent
Descriptions are deliberately excluded from this core federation profile.

The feed declares:

```json
{
  "data": {
    "sourceCount": 1,
    "verificationRequired": "independent-live-source-verification",
    "transitiveTrust": false
  },
  "extensions": {
    "registryFederation": {
      "profile": "urn:agent-web:registry-federation:0.1",
      "containsAssertions": false
    }
  }
}
```

## Receiver algorithm

1. Discover the peer through `/.well-known/agent-web`.
2. Verify the peer entry resource and its single typed federation link.
3. Fetch and verify the feed against the peer's discovery-authorized key.
4. Require the profile, non-transitive flags, exact source count, unique
   canonical Web discovery URLs, supported media types, and operator bounds.
5. Treat each URL only as a discovery hint.
6. Independently fetch every original site's Web discovery and crawl its
   bounded same-origin graph using the normal registry indexer.
7. Verify every original resource proof, canonical URL, publisher binding, and
   expiry before atomically replacing that site's local index snapshot.
8. Record per-source failures without importing peer assertions. Operators may
   choose fail-fast or best-effort behavior.

The receiver MUST NOT ingest peer-cached source documents, proof verdicts,
digests, names, ranking scores, or publisher identifiers as authoritative.
Search results after federation continue to cite the original source publisher
and discovery URL.

## Bounds and loops

The receiver applies explicit source and per-source resource limits. Duplicate
roots, the peer's own discovery root, malformed roots, count mismatch, unknown
profile versions, and feeds claiming transitive assertions are rejected before
any source is indexed. Multi-hop discovery is possible only when an operator
explicitly synchronizes another peer; imported sources are never automatically
re-exported as trusted assertions.

## Remaining work

This profile does not yet define peer allowlists, signed synchronization
receipts, incremental cursors, deletion/tombstone semantics, ranking exchange,
abuse reputation, scheduling, or convergence guarantees. Those features must
preserve the same non-transitive source-verification invariant.
