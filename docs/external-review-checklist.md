# External security and interoperability review

An internal test pass is not an external review. Give the reviewer a versioned review bundle, deployed architecture, operator and data-flow diagrams, threat model, public-beta evidence, key-manager attestations, NetworkPolicy probe results, restore-drill report, alert-delivery evidence, dependency inventory, and a private reporting channel. The reviewer must be organizationally independent from the implementation and operating teams.

The security scope should include DID/WNS/origin confusion, ANP HTTP-signature verification, nonce and bearer-token behavior across replicas, exact authorization scope, object-proof canonicalization, SSRF and DNS rebinding, redirect and proxy behavior, request/response bounds, HTML projection safety, Registry trust preservation, secret mounts, Vault ACLs and audit logs, TLS termination, gateway header behavior, container isolation, egress enforcement, backup tampering, partial drains, recovery, monitoring bypass, and denial-of-service limits.

Interoperability review must use at least two independent implementations or independently maintained clients and publishers. It should resolve exact handles, discover Agent Descriptions, verify DID and resource proofs, traverse linked resources, exercise a safe action, exercise an approved state-changing action, observe a denied action, validate cross-operator Moltbook/Forecast links, and confirm Registry indexing preserves source proof and publisher identity.

Acceptance requires:

- no unresolved critical or high findings;
- medium findings have explicit owners, deadlines, and compensating controls accepted by operators;
- every fix has a regression test and deployed retest;
- public CA, KMS/HSM, CNI, alert, backup, restore, and cross-operator evidence is attached;
- the reviewer signs a report containing scope, version/hash, methods, limitations, findings, retest status, and date;
- `docs/readiness.md` links the report and does not translate “not tested” into “passed.”

Use `scripts/export_review_bundle.py` to package the reviewable repository state. The bundle hash proves what was supplied; it does not prove reviewer independence or approval.
