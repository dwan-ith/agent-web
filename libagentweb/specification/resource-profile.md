# Agent Web Resource Profile 0.2

Status: experimental secure Web-native profile, revision 0.2.1.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are normative.

## Representation

The media type is `application/agent-web+json` while registration is pursued.
This profile is one interoperability component of Agent Web; it does not define
the entire ecosystem. A conforming site MAY be agent-only and MAY omit every
human-oriented representation.
The normative JSON Schema and JSON-LD context are packaged with `libagentweb`.

Every resource MUST include an HTTPS identity, semantic type, Agent Web kind,
typed links, affordance maps, publisher provenance, timestamps, application
data, and a W3C `DataIntegrityProof` using `eddsa-jcs-2022`.

`@id` MUST equal `provenance.canonical` and the transport URL. The proof
verification method MUST belong to `provenance.publisher`. The publisher MAY be
an HTTPS controller URL, a `did:web` identifier, or a `did:wba` identifier used
through the optional compatibility adapter. Core conformance MUST NOT require
ANP, WNS, or an Agent Description.

Schema validity alone is not proof validity. A consumer MUST obtain an
origin-authorized controller document, verify assertion-method authorization,
cryptographically verify the proof, and reject expired resources.

## Web discovery

An origin SHOULD publish `/.well-known/agent-web` using
`application/agent-web-discovery+json`. The document binds:

- the publisher controller;
- the exact Agent Web profile and entry point;
- the resource media type and optional human view;
- verification methods and assertion-method authorization.

The profile and entry point MUST use the discovery origin. When present, a
human view MUST use the discovery origin. `humanView` is optional; its absence
MUST NOT lower conformance or imply an incomplete website. This allows a
browser to discover and verify a publisher using HTTPS alone. ANP
Agent Descriptions MAY advertise the same entry point as an optional binding.

## Links and HTTP

A link contains a lower-case relation and HTTPS target. Defined relations
include `self`, `item`, `collection`, `next`, `prev`, `describedby`, `related`,
and `human-view`. Unknown relations are ignored unless understood.

Publishers SHOULD expose the Agent Web representation through HTTP content
negotiation or a typed `Link` with media type `application/agent-web+json`.
Browsers MUST bound bytes, time, resource count, redirects, origins, and network
destinations.

## Actions

An action declares input/output JSON Schemas, safety, idempotency,
authorization level, and one or more protocol interfaces. HTTP is the native
interface. `ANP`, `MCP`, and `A2A` are optional compatibility bindings.

For HTTP interfaces, `href` is an HTTPS target and `method` is the HTTP method.
A safe HTTP action MUST use GET or HEAD. Publisher claims of safety or
idempotency do not grant authorization and do not override HTTP method
semantics. `user-presence-required` requires explicit confirmation by an
interactive browser.

The present profile does not yet define protocol-neutral client authentication
for state-changing HTTP actions. Publishers MUST enforce their own
authentication, capabilities, quotas, and business policy. The reference
deployment retains its audited ANP HTTP-signature adapter for protected
mutations until a Web-native binding is specified and tested.

## Publisher requirements

A conforming secure publisher serves HTTPS, publishes origin-bound discovery,
signs every resource at the publishing boundary, emits typed links between
human and agent representations, distinguishes authentication from
authorization, and applies request bounds, auditability, rate controls, and
safe error handling.
