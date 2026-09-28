# Public-only example deployment and golden fixtures

These artefacts contain real signatures made using a one-time disposable key.
The private key was held only in memory and is not included. They demonstrate
structure and are regression fixtures, not live trust anchors or current metadata.
Expiry is intentional: do not extend dates or use them for production verification.
The example OpenID endpoint is descriptive and **does not exist**; generation for
a real issuer requires explicit configuration for an actual externally hosted service.

Regenerate into a new empty directory using the `public_fixtures` Rust example
when intentionally changing the publication profile. Tests compare normalized
shapes, validate schemas and check the original domain-linkage signature. Random
IDs, dates, proof bytes, key values and file digests are not deterministic snapshots.
