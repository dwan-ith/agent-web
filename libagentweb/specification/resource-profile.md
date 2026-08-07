# Agent Web Resource Profile 0.2

Status: experimental secure reference profile.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are normative.

## Representation

The media type is `application/agent-web+json` while registration is pursued.
The normative JSON Schema and JSON-LD context are packaged at:

- `libagentweb.schemas/agent-web-resource.schema.json`
- `libagentweb.schemas/agent-web-context.jsonld`

Every resource MUST include:

- HTTPS `@id`, semantic `@type`, and an Agent Web 0.2 kind;
- typed `links`;
- `properties`, `actions`, and `events` affordance maps;
- `provenance.publisher` as a DID-WBA DID;
- RFC 3339 creation and update times, exact canonical URL, optional expiry, and
  optional HTTPS sources;
- application-specific structured `data`;
- an ANP Appendix-B `DataIntegrityProof` using `eddsa-jcs-2022` and an
  `assertionMethod` authorized by the publisher DID.

The canonical URL MUST equal `@id`. The proof verification method MUST belong
to `provenance.publisher`. `updatedAt` MUST NOT precede `createdAt`, and
`expiresAt`, when present, MUST be later than `updatedAt`.

Schema validity alone is not proof validity. A consumer MUST resolve the DID
document, validate its DID-WBA key binding and proof, verify assertion-method
authorization, and cryptographically verify the object proof.

## Links

A link contains a lower-case `rel` and HTTPS `href`. Defined relations include:

- `self`, `item`, `collection`, `next`, and `prev`;
- `describedby` for an Agent Description;
- `related` for a cross-site resource graph edge;
- `human-view` for a human Web projection of the same source state.

Unknown relations are ignored unless understood. A browser MUST bound bytes,
time, resource count, redirects, origins, and network destinations.

## Actions

An action declares input/output JSON Schemas, `safe`, `idempotent`,
`authorizationLevel`, and one or more protocol interfaces.

`authorizationLevel` is:

- `normal`: no extra user-presence confirmation is required by this profile;
- `user-presence-required`: a browser MUST obtain explicit confirmation before
  invoking the action.

This field is not a complete authorization system. Publishers still enforce
their own roles, capabilities, quotas, and business policy. Every reference RPC
call authenticates even when the advertised action is safe.

The ANP interface uses `href` for the HTTPS JSON-RPC endpoint and `method` for
the OpenRPC method.

## ANP integration

An Agent Description advertises:

```json
{
  "agentWeb": {
    "profile": "https://site.example/agent-web/0.2",
    "version": "0.2",
    "entryPoint": "https://site.example/resources/index.json",
    "resourceMediaType": "application/agent-web+json",
    "humanView": "https://site.example/"
  }
}
```

The Agent Description remains an ANP document. In the secure profile it also
carries an object proof from the same DID named by `identifier`, and that DID
document authorizes the exact Agent Description service URL.

## Publisher requirements

A conforming secure publisher:

- serves only HTTPS with an operator-controlled certificate;
- hosts its DID-WBA document at the DID-derived path and publishes an ANP
  discovery index;
- protects RPC with DID-WBA HTTP Message Signatures, content digests,
  timestamp windows, and one-use nonces;
- disables legacy DID-WBA authentication unless a separately documented
  compatibility profile is enabled;
- derives caller identity from verified request context;
- treats authentication and authorization as different decisions;
- signs each resource at the publishing boundary;
- emits an HTML canonical `Link` header for human projections;
- applies request bounds, auditability, rate controls, and safe error handling.
