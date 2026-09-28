# Configuration reference

All fields are optional; unknown fields fail. CLI `--suite`, `--status-list`,
`--config`, and explicit resource arguments take precedence. TOML paths resolve
against the process working directory. Use absolute paths for automation.

```toml
default_suite = "issuer"
default_status_list = "/srv/holon/private/status/main.json"
development_origins = []

[resources."https://issuer.example/.well-known/did.json"]
path = "/srv/holon/pins/did.json"
sha256 = "REPLACE_WITH_SHA256_OF_EXACT_FILE_BYTES"
expires = "2026-09-27T12:05:00Z"
media_type = "application/did+ld+json"
retrieved_at = "2026-09-27T12:00:00Z"

[contexts."https://issuer.example/contexts/product-v1"]
path = "/srv/holon/contexts/product-v1.jsonld"
sha256 = "REPLACE_WITH_SHA256_OF_EXACT_FILE_BYTES"
expires = "2027-01-01T00:00:00Z"
media_type = "application/ld+json"

[schemas."https://issuer.example/schemas/product-v1"]
full = "/srv/holon/schemas/product-full.json"
disclosure = "/srv/holon/schemas/product-disclosure.json"
context = "https://issuer.example/contexts/product-v1"
sha256 = "REPLACE_WITH_FULL_SCHEMA_SHA256"
disclosure_sha256 = "REPLACE_WITH_DISCLOSURE_SCHEMA_SHA256"
```

This is a configuration template, not a working trust anchor. Replace every path,
digest, and expiry deliberately. Custom schemas must be self-contained Draft
2020-12 JSON Schema; external `$ref`/`$dynamicRef` retrieval is denied. Schemas
validate the Holon subject. Pin both full and disclosure variants under one signed
schema ID. Custom contexts are permitted only when explicitly pinned; built-in
contexts cannot be overridden. Contexts never trigger network retrieval.

Validated generated resources are indexed in `DATA/config/resources.json` with
short expiries; explicit configured resources take precedence. No automatic
network cache is created. A stale pin causes failure rather than network fallback.
Offline resources are content pins, not issuer trust policies.

Optional `[openid]` contains explicitly supplied metadata for an externally
operated OpenID4VCI service. The CLI is not an OAuth or issuance HTTP server.
`credential_issuer` must equal the HTTPS origin. `credential_endpoint` is required;
`nonce_endpoint` and `deferred_credential_endpoint` are optional explicit HTTPS
URLs. `credential_configurations_supported` must describe `ldp_vc`, VC2 plus the
Holon context, `VerifiableCredential`/`HolonCredential` types, `did:web` binding,
and signing suites supported by the published active keys. Do not advertise an
endpoint merely because the CLI can create metadata for it. Endpoint operation,
OAuth behavior and remote OpenID conformance are the external operator's responsibility.

Trust policy JSON is documented by the example template and Rust `trust::Policy`.
`acceptedDomains` means **issuer HTTPS origins**, not VP audiences. The latter are
always checked against the verifier's explicit `--domain`. `independentSources`
maps issuer DID to an operator-established organizational group; two DIDs in the
same group count once. Only equality comparisons are supported. Unsupported
comparison operators fail validation rather than becoming no-ops.

Pinned status credentials additionally require `retrieved_at`. Verification enforces
the signed TTL (default 300,000 milliseconds), regardless of a longer configured
pin expiry. Other pinned resources do not require this cache timestamp.
