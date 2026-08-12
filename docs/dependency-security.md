# Runtime dependency security

The production dependency lock is hash-bound for CPython 3.13 on Linux/amd64,
but hashes are an integrity control rather than a vulnerability assessment.
On 2026-08-12, `pip-audit 2.10.1` checked every entry in
`deploy/requirements.lock` against the PyPI advisory service.

The audit found `PYSEC-2026-3552` in `cryptography 49.0.0`. The lock now uses
`cryptography 50.0.0`, and the replacement Linux wheel's filename, project
metadata, version, size, and SHA-256 are covered by the 2026-08-12 requirements
evidence.

One unfixed transitive advisory remains visible: `PYSEC-2026-1325`
(`CVE-2024-23342`) affects timing-sensitive signing and key-agreement operations
in `ecdsa 0.19.2`. `anp 0.9.2` declares that package as a dependency, but its
Python sources do not import it, and Agent Web's runtime sources do not import
it. Agent Web uses Ed25519 for DID, object-proof, and HTTP-message-signature
operations; ANP's ECDSA support in the exercised paths uses `cryptography`, not
the `python-ecdsa` package.

This is a containment decision, not a claim that the installed package is
fixed. `scripts/validate_dependency_policy.py` fails if the pinned ANP or ecdsa
version changes, or if either ANP or Agent Web runtime code begins importing
`ecdsa`, including direct constant-name dynamic imports. Do not enable
`python-ecdsa` signing, ECDH, or new ANP ECDSA code paths under this exception.
Replace the dependency or re-audit the boundary when ANP changes, and review
this exception no later than 2026-09-12.

The expected online audit command is:

```powershell
pip-audit -r deploy\requirements.lock --require-hashes --disable-pip `
  --ignore-vuln PYSEC-2026-1325
```

An external reviewer must still inspect this exception and may reject it for a
public deployment. The repository therefore does not claim an advisory-free
Python environment.
