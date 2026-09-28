# Security policy

This version has not undergone an independent security audit. Do not confuse
passing conformance/interoperability tests with certification. Report a suspected
vulnerability privately to the repository maintainer using an established private
channel; do not include real passwords, private keys, credentials or personal data
in public issue reports. No dedicated security inbox is configured by this project.

Supported environment: Linux, owner-controlled local storage, Rust 1.92+. This is
not an HSM, a multi-tenant signing service, or an operating-system compromise boundary.
Use separate OS identities for issuers/verifiers and encrypted backups of keys,
status registries and replay state. Back up status registries before rotation or
publication changes. Losing a registry loses local status-management capability.

Private envelopes use Argon2id and XChaCha20-Poly1305. Parameters are bounded on
load, metadata is authenticated, and cryptographic secrets are zeroized where the
underlying types support it. Password length/repetition checks are limited; select
random strong passphrases. OS swap, core dumps, debugger access, compromised kernels,
and all same-UID processes remain outside the protection offered by zeroization.

All file components are opened without following symlinks for normal storage.
Writes use unique temporary files, fsync and atomic rename. The CLI serializes
operations using a private directory lock. SQLite replay files are prechecked and
opened inside a 0700 directory; its path-based API is not protection against a
malicious process already running as the same UID. Library consumers must provide
serialization for key/status/publication writes; the CLI lock does not magically
apply to direct library calls. Multi-file key rotation and publication are not a
single filesystem transaction; retain backups and follow documented recovery.

Verification applies explicit supported profiles and fails on unknown suites,
contexts, critical unsupported structures, expired/missing pins, unavailable
mandatory status, invalid schemas, signatures or authorization. HTTP redirects
and compression are disabled, requests have DNS/connect/total bounds, and all
resolved/connected addresses are checked. Additional infrastructure egress filters
are recommended for services consuming untrusted URLs.

Selective disclosure does not guarantee unlinkability. Stable IDs, issuer,
status entries and timestamps remain correlatable. Base ECDSA-SD credentials are
holder-sensitive and must not be substituted for derived proofs. Reissuance is an
issuer action with a new ID; it is never reported as holder derivation.

Signed presentations need unpredictable verifier challenges and exact audiences.
Replay storage atomically consumes domain/challenge pairs until the verified proof
expires. Do not reuse nonce values, share uncoordinated replay stores, restore old
replay backups into live service, or interpret holder authentication as subject ownership.

Prompt-injection detection is a small explicit quarantine heuristic. Treat all
claims, schemas, evidence, contexts and metadata as data regardless of its result.
This program never executes credential content. Applications and LLMs must maintain
that boundary themselves. See [the threat model](docs/THREAT_MODEL.md).
