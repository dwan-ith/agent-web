# Agent Web security policy

Agent Web is a security-sensitive reference implementation. Until a deployment publishes an operator-owned private reporting address, do not expose it as a public beta. Each public operator must publish a working `mailto:` or HTTPS security contact in the public-beta manifest and test that reports reach an on-call human.

Report suspected authentication bypass, signature or DID confusion, SSRF, cross-operator trust failure, secret disclosure, authorization bypass, replay, persistent data corruption, or recovery failure privately. Include the affected version, endpoint, minimal reproduction, impact, and whether exploitation is active. Do not include live private keys, bearer tokens, Vault tokens, personal data, or destructive proof-of-concept payloads.

The receiving operator should acknowledge a critical report within one hour and a high-severity report within one business day, preserve evidence, assign an incident commander, and coordinate disclosure across affected operators. A fix is not complete until regression tests pass, deployed evidence exists, compromised credentials are rotated, and downstream operators receive an actionable advisory.

Good-faith research against an operator that has explicitly opted into testing should minimize data access and service disruption. This repository cannot grant authorization for systems run by independent operators; obtain written scope from each operator first.

Supported security work covers the current `0.2.x` reference line. No claim is made that a local checkout, example manifest, or statically validated deployment has received an external audit.
