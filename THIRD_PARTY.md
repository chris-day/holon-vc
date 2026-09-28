# Third-party provenance

Rust dependencies retain their own licenses, recorded in Cargo.lock and crate metadata.

The ECDSA-SD grouping/orchestration in `src/disclosure.rs` follows the published
algorithms and the organization of Spruce Systems' SSI 0.3.0 selective-disclosure
primitives (Apache-2.0): https://github.com/spruceid/ssi . Changes: bounded Sophia
RDFC-1.0 canonicalization, explicit base-proof verification, lexical N-Quads ordering,
strict proof/component validation, and content-free errors. Cryptographic primitives
are provided by RustCrypto and ed25519-dalek, not implemented here.

SSI source copyright: Spruce Systems, Inc. Licensed under Apache License 2.0:
The full license is included at `licenses/Apache-2.0.txt`. No endorsement is implied.
