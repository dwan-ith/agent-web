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

Publishers SHOULD set `provenance.expiresAt` on every resource whose content
is volatile; an unbounded lifetime means a verification cache or offline copy
of the document stays acceptable forever. Proof `created` timestamps are not
expiry: only `provenance.expiresAt` bounds how long a verified document may be
trusted without refetching it from its canonical URL.

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

## Collections and pagination

A collection resource MUST stay bounded: an entry or directory resource that
could grow without limit MUST advertise its members through paginated child
collections instead of embedding every member inline. A pagination page is an
ordinary signed collection whose `self` link matches its transport URL exactly,
whose `item` links address that page's members, and which carries a `next`
link when a further page exists and a `prev` link when one does. Publishers
SHOULD keep page sizes bounded (the reference publishers use 50) and report
the total count in `data` alongside the page's own count. A consumer follows
`next` links under its own traversal budget; absence of a `next` link means
the collection ended.

## Action results

An invoked action returns ordinary signed Agent Web resources. The response
resource's `@id` MUST use the serving origin of the advertised interface URL.
When the interface origin equals the discovery origin, the result is verified
against that discovery document as usual. When an action is served by another
allowed origin, browsers MUST fetch that origin's own `/.well-known/agent-web`,
check that the result's publisher matches it, and verify the proof against its
authorized keys. A signature from the advertising site does not vouch for a
document served by a different origin.

## Actions

An action declares input/output JSON Schemas, safety, idempotency,
authorization level, and one or more protocol interfaces. HTTP is the native
interface. `ANP`, `MCP`, and `A2A` are optional compatibility bindings.

For HTTP interfaces, `href` is an HTTPS target and `method` is the HTTP method.
A safe HTTP action MUST use GET or HEAD. Publisher claims of safety or
idempotency do not grant authorization and do not override HTTP method
semantics. `user-presence-required` requires explicit confirmation by an
interactive browser.

The present profile defines protocol-neutral client authentication for
state-changing HTTP actions in `authenticated-http-actions.md` (experimental):
a strict RFC 9421 Ed25519 profile with RFC 9530 body digests, HTTPS caller
controllers, short lifetimes, and durable one-use nonces. Publishers MUST
still enforce their own authorization, capabilities, quotas, and business
policy; a valid signature grants no action authority by itself.

## Publisher requirements

A conforming secure publisher serves HTTPS, publishes origin-bound discovery,
signs every resource at the publishing boundary, emits typed links between
human and agent representations, distinguishes authentication from
authorization, and applies request bounds, auditability, rate controls, and
safe error handling.
