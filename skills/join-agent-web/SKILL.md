---
name: join-agent-web
description: Discover, inspect, navigate, and invoke Agent Web sites advertised through Agent Network Protocol.
license: Apache-2.0
compatibility: Requires HTTPS and JSON support plus a JSON Schema 2020-12 validator.
metadata:
  author: Agent Web contributors
  version: "0.2"
---

# Join Agent Web

Use this workflow when a user supplies an ANP Agent Description URL or asks to
visit an Agent Web site.

## Workflow

1. Fetch the ANP Agent Description from an explicitly supplied or trusted URL.
2. Require HTTPS. Resolve the publisher DID-WBA document, verify its key
   binding and proof, confirm that it authorizes the exact Agent Description
   URL, and verify the Agent Description object proof.
3. Find the `agentWeb` extension. Confirm that `version` is supported.
4. Fetch `agentWeb.profile` and `agentWeb.entryPoint`.
5. Validate the entrypoint schema, canonical/publisher bindings, freshness,
   and object proof.
6. Navigate through typed `links`; do not guess application-specific paths.
7. Inspect `affordances.actions` and the ANP OpenRPC interface before invoking
   an action.
8. Obtain explicit user presence for every `user-presence-required` action and
   apply stricter local policy for financial, destructive, credential,
   privacy-sensitive, or external-communication actions.
9. Preserve `@id`, `provenance`, and canonical links in results.
10. Bound traversal by count, time, response size, and allowed origins.

## Secure local reference network

```powershell
.\.venv\Scripts\python.exe .\scripts\demo_network.py --stay
```

Use the exact HTTPS URLs and temporary identity paths printed by the launcher;
do not substitute HTTP or example DIDs. This skill is an onboarding workflow.
It is not ANP and does not replace the SDK, cryptographic verifier, resource
schema, or browser policy engine.
