# Incident response runbook

## Activation

Declare an incident when integrity, confidentiality, authentication, authorization, availability, key custody, DNS/WNS control, or recoverability may be compromised. Assign an incident commander, operations lead, security lead, communications lead, and recorder. Use an out-of-band channel if Agent Web identity or messaging is suspect. Record times in UTC and preserve original logs, Vault audit events, certificate data, manifests, and database copies with hashes.

Severity 1 covers active key compromise, authorization bypass, cross-operator forgery, destructive corruption, or broad secret disclosure. Freeze changes, page all affected operators, and begin containment immediately. Severity 2 covers credible limited compromise or sustained outage without proven integrity loss. Lower severities follow normal tracked remediation.

## Common first actions

1. Confirm the signal from a second source; do not dismiss it only because readiness is green.
2. Preserve evidence before rotating or restoring. Restrict access to the evidence set.
3. Enter maintenance on every known writer replica. If this cannot be done safely, remove the service from the gateway or deny mutation traffic at the network layer.
4. Revoke exposed workload, operator, metrics, Vault, and access tokens. Do not reuse a suspected secret.
5. Identify the earliest plausible compromise time and affected DIDs, WNS generations, grants, resources, backups, downstream registries, and operators.
6. Communicate confirmed facts, uncertainty, user action, and the next update time. Never claim proof restoration before verification passes.

## DID assertion-key or Vault compromise

Disable the Vault token first; retain the key and audit log for evidence unless the HSM/KMS operator requires immediate disablement. Stop signing, remove gateway traffic, and identify every signature after the compromise time. Provision a successor DID/key through the separate rotation role, publish and verify the transition proof, update the exact WNS binding with a higher generation, and notify registries and peers to reject the old DID. Reissue resources under the successor identity only after source state integrity is established. Rotate the separate access-token key and invalidate existing bearer sessions.

## DNS, TLS, or WNS takeover

Freeze mutations and signing. Compare registrar, DNS provider, CT/CA, WNS history, and DID documents with the last accepted evidence bundle. Revoke unauthorized certificates through the CA, restore registrar and DNS controls with fresh credentials, increment the WNS binding generation, and require browsers to use the new minimum generation. Treat resources fetched during the takeover window as untrusted even if transport validation succeeded.

## SSRF or unexpected egress

Apply a deployment egress deny immediately and preserve DNS answers, resolved addresses, connection logs, request IDs, and NetworkPolicy/CNI events. Rotate any credential reachable from the destination. Verify both application DNS pinning and live CNI enforcement. Do not reopen egress until the exact destination, redirect behavior, proxy settings, and mixed-answer handling have regression coverage.

## Data corruption or destructive mutation

Stop every writer, create a forensic copy, run SQLite integrity checks on the copy, and identify the last known-good verified backup. Compare audit records and signed resource digests. Restore only into a new directory, validate it offline, start a quarantined instance, and run resource, authorization, WNS, and federation checks before gateway promotion. Never overwrite the damaged source during investigation.

## Monitoring or alert-delivery failure

Treat silent monitoring as an availability incident. Confirm publisher `/ready` directly with public CA validation, inspect Prometheus targets/rules, and send a synthetic firing and resolved notification. Restore the receiver secret and record delivery timestamps. A statically valid Alertmanager file is not delivery evidence.

## Closure

Closure requires containment, eradication, verified recovery, secret and key rotation where applicable, cross-operator notification, a written timeline, identified control failures, regression tests, and owners with deadlines. Publish a post-incident report that separates verified facts from inference and records whether any evidence remains unavailable.
