# Threat model

Assets: issuer/holder secret keys and passwords, status allocations and revocation
state, replay history, scope-specific trust policies, hidden credential values,
and the distinction between authentic claims and trusted/corroborated claims.

Trust boundaries: untrusted input JSON, HTTPS endpoints, downloaded DID documents,
local explicitly pinned contexts/schemas, private owner-controlled storage, and
external policy/LLM consumers. TLS/DNS and local administrator configuration are
trust assumptions, not issuer authority by themselves.

| Threat | Control and validation | Residual boundary |
|---|---|---|
| Key theft/substitution | AEAD key envelope, KDF, permissions, suite/controller/fingerprint checks | Same UID/OS compromise; no HSM |
| Forged or altered VC | Real Ed25519/P-256 suite operations, official vectors, independent JS interoperability | Cryptographic adapter needs independent review |
| Wrapping/algorithm confusion | Single proof object, exact type/suite dispatch, authorized relationship | Only documented narrow profiles accepted |
| JSON-LD data loss | Pinned contexts, strict expansion, duplicate/null rejection | RDF-equivalent JSON ordering is intentionally not byte-bound |
| Unsafe schema/context retrieval | Local content pins, no remote context loading or external schema refs | Administrator-selected custom schemas/contexts are trusted configuration |
| False claim authority | Scoped pins and explicit policies; authenticity separate from truth | Policies and organizational source independence can be wrong |
| Fake corroboration | Signed active evidence, explicit equality rules, independent groups | No general scientific or semantic truth engine |
| Status outage/revocation rollback | Signed lists, permanent registry revocation, freshness/pins, no active-on-error | Valid caches impose bounded revocation latency; protect registry backups |
| Replay/audience substitution | Holder auth, exact nonce/domain, <=5-minute proof, SQLite uniqueness | Verifier must issue random challenges and preserve durable store |
| SSRF/rebinding/decompression | Address checks, DNS-pinned connections, no proxy/redirect/compression, size/time bounds | Service deployments should also enforce network egress policy |
| File overwrite/symlink | Descriptor-relative paths, NOFOLLOW, atomic rename, explicit force | Same-UID races and multi-file crash consistency are limited |
| Hidden-value leakage | Genuine statement derivation, negative canary tests, redacted errors | IDs/status/timing correlate; original credentials remain sensitive |
| Metadata staleness/conflict | Expected fingerprint, signed linkage, digests, schemas, cross-document checks | Static deployment must publish consistent generations |
| Prompt injection | No evaluation of credential text, optional explicit quarantine | Heuristic is not complete; agents need their own data/instruction boundary |

Canonicalization rejects resource-exhausting graphs instead of falling back to a
different algorithm. Inputs/HTTP responses are limited to 4 MiB; decoded status
lists to 16 MiB; expanded graphs to 50,000 quads. DNS/connect/HTTP timeouts are
5/5/15 seconds. No heuristic signature acceptance or simulated disclosure exists.

Adversarial tests include duplicate properties, invalid purposes/keys/schemas,
modified claims, unknown contexts, unavailable status, all status transitions,
replay and audience mismatch, missing/contradictory evidence, instruction quarantine,
public key rotation, malformed metadata, redirects, private addresses, HTTP
compression, oversized responses and private-material rejection. Exact results
and uncompleted gates, if any, are recorded in STATUS.md.
