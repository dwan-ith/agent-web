# Managed signing and key custody

Agent Web supports a Vault Transit Ed25519 assertion key for both publisher object proofs and agent-browser DID-WBA HTTP signatures. The private assertion key never enters the Agent Web process. The runtime fetches the public key, requires a non-derived signing-capable `ed25519` key, asks Transit to sign the exact PureEdDSA input, and verifies every returned signature locally before publishing or sending it.

Use a non-exportable, non-derived Transit key per publisher and a different narrowly scoped Vault token per workload. A minimal Moltbook policy is:

```hcl
path "transit/keys/moltbook" {
  capabilities = ["read"]
}

path "transit/sign/moltbook" {
  capabilities = ["update"]
}
```

Do not grant key creation, configuration, rotation, export, backup, import, decrypt, or delete to the runtime identity. Provisioning and rotation belong to a separate operator role with audited approval. Deliver the workload token through an authenticated workload identity or a rotated agent sink file; never put it in an image, environment variable, Compose document, or log.

The current ANP verifier library still accepts PEM keys for signing its short-lived bearer access tokens. Vault-backed publisher mode therefore mounts a separate `access-token-key.pem`. That key is not present in the DID document and cannot sign Agent Web resources. Replicas that accept each other's bearer tokens must share this access-token key through a secret manager, or route a token to the issuing replica until the ANP library exposes a remote JWT signer. This is a documented residual custody and HA boundary, not a claim that every cryptographic key is already HSM-backed.

Apply `compose.json` together with `compose.vault.json`. Each identity mount then contains only `did.json` and `access-token-key.pem`; its operations mount also contains `vault.token`. Before serving traffic, use `verify_vault_signer.py` to prove that the configured key matches the DID and can sign a fresh challenge. Preserve the JSON evidence, Vault audit event, key configuration, key version, and HSM/KMS attestation in the external review bundle.
