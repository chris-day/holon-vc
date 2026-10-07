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


The official Schema.org context snapshot in `contexts/vendor/` was retrieved from
https://schema.org/docs/jsonldcontext.json on 2026-10-07. Its adjacent provenance
file records its SHA-256 digest. Schema.org sponsors Google, Yahoo, Microsoft and
Yandex license the schema under CC BY-SA 3.0:
https://creativecommons.org/licenses/by-sa/3.0/ . See
https://schema.org/docs/terms.html . The snapshot is unmodified; generated product
contexts select definitions and scope them under a Holon product property. The
attribution and share-alike terms apply to those Schema.org-derived mappings;
`profiles/gs1-product-v1/NOTICE.txt` carries this attribution with the output.
