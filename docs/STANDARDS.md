# Standards and interoperability register

The authoritative requirements are `Holon_VC_Implementation_Prompt_v1.0.0.md`.
Test success is not a security audit or certification.

| Standard/profile | Version | Implementation and validation |
|---|---|---|
| VC Data Model | 2.0, W3C Recommendation 2025-05-15 | Application validation; issuer and verifier checks tracked in STATUS.md |
| Data Integrity | 1.0, W3C Recommendation 2025-05-15 | Explicit suite dispatch and independent proof/policy stages |
| EdDSA Cryptosuites | 1.0, W3C Recommendation 2025-05-15 | `eddsa-rdfc-2022`; W3C signatures reproduced exactly; Digital Bazaar bidirectional tests |
| ECDSA Cryptosuites | 1.0, W3C Recommendation 2025-05-15 | `ecdsa-sd-2023`, P-256 only; base and derived verification; cross-implementation disclosure |
| Legacy EdDSA | Community Group final report 2022-07-24 | `Ed25519Signature2020`, URDNA2015, explicit issuance opt-in |
| Controlled Identifiers | 1.0, W3C Recommendation 2025-05-15 | Relationship and controller checks, not trust by download |
| did:web | Community method, snapshot reviewed 2026-09-27 | Origin and path translation; HTTPS retrieval |
| RDF Dataset Canonicalization | RDFC-1.0, Recommendation 2024-05-21 | Sophia 0.10.0, SHA-256, preserved blank-node labels |
| Ed25519 | RFC 8032, January 2017 | ed25519-dalek 2.2.0 strict verification |
| JSON-LD | 1.1, Recommendation 2020-07-16 | SSI/json-ld; strict undefined-term rejection; pinned loaders |
| Status | Bitstring Status List 1.0, Recommendation 2025-05-15 | Signed single-bit revocation/suspension; MSB ordering, gzip bounds, signed TTL enforced |
| OpenID4VCI | Final 1.0 | Optional metadata for explicitly configured external endpoints; no server implementation |

RDFC test fixtures include all 86 manifest entries. 84 applicable SHA-256 cases
are evaluated, including label maps and negative/resource-limit handling; two
SHA-384 entries are not applicable to the selected Ed25519/P-256 profile. Graphs
that exceed the configured canonicalization budget fail closed. No alternate
canonicalization or signature verification is attempted after a failure.

JCS (RFC 8785) is not substituted for RDF canonicalization. No JCS issuance suite
is advertised. Selective disclosure is statement-level ECDSA-SD; it does not
promise unlinkability. Original proof values contain holder derivation material
and must not be published to verifiers in place of derived proofs.

The approved VC 2.0 domain-linkage profile uses `validFrom`/`validUntil`. It is
application-specific and is **not** conformant to DIF's established Domain Linkage
Credential profile requiring `issuanceDate`/`expirationDate`. This is an explicit
user-selected compatibility limitation, not a cryptographic downgrade.

`interop/` is test-only JavaScript. Production cryptographic operations run in
Rust and do not invoke Node. Exact test dependency versions are in its lockfile.

## Application interoperability boundaries

- VC2 Holon profile: exactly one subject object and one proof; string did:web issuer;
  required ID, validFrom, subject schema, and both revocation/suspension entries.
  Other conforming VC shapes are rejected, not partially verified.
- `HolonSubjectSchema` validates the subject against pinned full/disclosure schemas;
  it is not the W3C whole-credential JSON Schema profile.
- Only did:web, Ed25519 Multikey/Ed25519VerificationKey2020 and P-256 Multikey are
  resolved. No did:key, did:jwk, JWT VC, SD-JWT, BBS, proof chains or historical DID
  protocol is advertised. Legacy crypto interoperation is tested separately from
  legacy ecosystem DID key-class and VC1 expectations.
- Bitstring status implements revocation and suspension, statusSize=1, minimum
  131072 bits, base64url multibase+gzip; multi-bit messages are unsupported.
  One-day list validity and a default 300-second cache TTL are explicit defaults.
  A pin cannot bypass the signed TTL by declaring a later expiry.
- Presentations use modern Ed25519 authentication. Evidence supports digest
  integrity and explicitly compared signed Holon credentials, not generic proof
  of external factual truth. Organizational independence is configured policy.
- Optional OpenID metadata describes explicitly configured external endpoints;
  no OpenID authorization/issuance server is provided or implied.
- Publication is atomic per file with manifest-last consistency detection, not a
  multi-file database transaction. Linux storage, no HSM, no Windows port.

Modern suite orchestration uses Sophia RDFC with SSI JSON-LD selection and
RustCrypto primitives. This focused standards adapter addresses SSI's missing
base-proof verifier and older canonicalization integration without replacing
cryptography with simulations. These are implemented workarounds, not claims that
upstream SSI alone implements every requested profile. Independent security review
of this glue remains necessary before a production assurance claim.

Primary references: [VC2](https://www.w3.org/TR/vc-data-model-2.0/),
[Data Integrity](https://www.w3.org/TR/vc-data-integrity/),
[EdDSA](https://www.w3.org/TR/vc-di-eddsa/),
[ECDSA-SD](https://www.w3.org/TR/vc-di-ecdsa/),
[RDFC](https://www.w3.org/TR/rdf-canon/),
[Bitstring Status](https://www.w3.org/TR/2025/REC-vc-bitstring-status-list-20250515/),
[did:web](https://w3c-ccg.github.io/did-method-web/),
[DIF linkage](https://identity.foundation/well-known-did-configuration/resources/did-configuration/),
[OpenID4VCI Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html).
