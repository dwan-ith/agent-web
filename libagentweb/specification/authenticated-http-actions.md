# Agent Web Authenticated HTTP Actions 0.1

Status: implemented experimental profile, August 2026.

This binding authenticates an Agent Web caller without ANP, DID-WBA, an Agent
Description, HTML, cookies, or bearer tokens. It is a deliberately strict
application profile of RFC 9421 HTTP Message Signatures and RFC 9530
`Content-Digest`; it is not a general implementation of either RFC.

## Advertised interface

An authenticated action declares its transport security on the HTTP interface:

```json
{
  "protocol": "HTTP",
  "href": "https://knowledge.example/actions/annotations",
  "method": "POST",
  "contentType": "application/json",
  "security": "http-message-signature"
}
```

The browser MUST refuse this interface unless it holds a caller controller and
an Ed25519 key authorized by that controller's `authentication` relationship.
The publisher MUST authenticate before applying a separate authorization
policy. A valid signature grants no action authority by itself.

## Caller controller

A caller identity is an absolute HTTPS controller URL. Agent browsers SHOULD
publish it at `/.well-known/agent-web-caller` on their own origin. The minimal
document is:

```json
{
  "id": "https://browser.example/.well-known/agent-web-caller",
  "verificationMethod": [{
    "id": "https://browser.example/.well-known/agent-web-caller#key-1",
    "type": "Multikey",
    "controller": "https://browser.example/.well-known/agent-web-caller",
    "publicKeyMultibase": "z..."
  }],
  "authentication": [
    "https://browser.example/.well-known/agent-web-caller#key-1"
  ]
}
```

Publishers MUST resolve controller keys through operator policy: a pinned
configuration, an already verified cache, or a bounded HTTPS resolver with an
explicit trust-on-first-use or grant workflow. They MUST NOT turn an
unvalidated caller header into an unrestricted server-side fetch. The native
knowledge reference uses pinned operator configuration.

## Signature profile

The signature label is `agentweb`; the algorithm is Ed25519. These components
are mandatory and appear in exactly this order:

```text
"@method"
"@target-uri"
"content-digest"
"content-type"
"agent-web-caller"
```

`created`, `expires`, `keyid`, `nonce`, and `alg="ed25519"` are mandatory
signature parameters. The maximum signature lifetime is 300 seconds. The
nonce is caller-generated, unpredictable, and claimed atomically once per
caller. JSON bodies use `Content-Type: application/json`; `Content-Digest`
uses the RFC 9530 `sha-256` dictionary member over the exact HTTP content.

Example fields:

```text
Agent-Web-Caller: https://browser.example/.well-known/agent-web-caller
Content-Digest: sha-256=:...:
Signature-Input: agentweb=("@method" "@target-uri" "content-digest" "content-type" "agent-web-caller");created=...;expires=...;keyid="...#key-1";nonce="...";alg="ed25519"
Signature: agentweb=:...:
```

The target URI is the public URI advertised in the verified resource. A
publisher behind a reverse proxy MUST reconstruct it from trusted deployment
configuration, not untrusted forwarding headers.

## Verification order

1. Enforce HTTPS authority, body-size, media-type, and route policy.
2. Select an operator-trusted controller document using `Agent-Web-Caller`.
3. Parse only this strict profile and reject missing or extra shapes.
4. Check creation, expiry, key ownership, and `authentication` authorization.
5. Recompute `Content-Digest`, rebuild the RFC 9421 signature base, and verify
   Ed25519.
6. Atomically claim `(caller, nonce)` in shared durable state.
7. Apply the endpoint's independent caller/action/resource authorization.
8. Derive authorship and audit identity from verified context, never JSON.

Authentication failures use 401; authenticated but unauthorized callers use
403. A successful response is still an ordinary signed Agent Web resource and
is verified against publisher Web discovery by the browser.

## Interoperability boundary

Independent implementations are expected to reproduce the exact signature
base and wire fields. The repository test vectors cover tampered body, method,
target URI, caller, expired signatures, unauthorized keys, and nonce replay.
Cross-language conformance is implemented: Python and TypeScript sign and
verify from one committed vector file, and both languages also verify
`eddsa-jcs-2022` resource proofs against a shared Data Integrity vector file.
