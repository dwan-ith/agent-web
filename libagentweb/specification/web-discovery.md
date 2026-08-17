# Agent Web Web-Native Discovery 0.1

Status: implemented experimental binding.

`GET /.well-known/agent-web` returns
`application/agent-web-discovery+json`. The HTTPS origin is the discovery trust
root. The document is also a W3C Data Integrity controller document for keys
that sign that origin's Agent Web resources.

```json
{
  "id": "https://example.com/.well-known/agent-web",
  "publisher": "https://example.com/.well-known/agent-web",
  "agentWeb": {
    "version": "0.2",
    "profile": "https://example.com/agent-web/0.2",
    "entryPoint": "https://example.com/resources/index",
    "resourceMediaType": "application/agent-web+json",
    "humanView": "https://example.com/"
  },
  "verificationMethod": [
    {
      "id": "https://example.com/.well-known/agent-web#key-1",
      "type": "Multikey",
      "controller": "https://example.com/.well-known/agent-web",
      "publicKeyMultibase": "z..."
    }
  ],
  "assertionMethod": [
    "https://example.com/.well-known/agent-web#key-1"
  ]
}
```

The `profile` and `entryPoint` values MUST use the discovery origin. When
present, `humanView` MUST also use that origin. `humanView` is explicitly
optional: native Agent Web sites need no World Wide Web projection. Verification
method identifiers MUST be fragments of `publisher` and
every assertion method MUST reference one published verification method.

The current reference publishers use DID-WBA identifiers in `publisher` for
backward compatibility but repeat their Multikey material in this HTTPS
document. Core clients verify resources directly against the discovery
document and do not need to resolve the DID or load ANP code.
