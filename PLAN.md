# Approved implementation plan

Authority: `Holon_VC_Implementation_Prompt_v1.0.0.md`. Working directory:
`/var/software/gitrepos/holon-vc`. The inaccessible Windows destination was
superseded by the user's subsequent Linux working-directory instruction.

## Decisions

- Linux first; stable Rust; one library and `holon-vc` binary with the specified modules.
- Modern Ed25519 (`eddsa-rdfc-2022`) default; legacy verification and explicitly
  opted-in issuance; genuine P-256 `ecdsa-sd-2023` holder derivation.
- Library primitives only. Focused standards adapters/patches require vectors,
  independent interoperability tests, and review before a production claim.
- Full and disclosure schema profiles; typed source/evidence/relationships.
- Evidence corroboration uses explicit claim comparisons and independent-source
  rules, never downloaded content alone.
- VC 2.0 domain linkage is an application profile, explicitly incompatible with
  the established DIF profile's VC 1.x date requirements.
- Pin contexts; no implicit network loading. Authenticated assertions are not truth.
- Persistent transactional replay storage; fail closed on unavailable mandatory checks.

## Known research findings

SSI 0.16.0 / data-integrity-suites 0.4.0 exposes the requested suites, but its
ECDSA-SD verifier rejects base proofs. A separate base-proof validator is required
before derivation. SSI RDF 0.1.1 uses URDNA2015; modern suite processing must be
validated against RDFC-1.0 and use a conforming adapter. Sophia canonicalization
0.10.0 exposes canonical label mappings and processing limits. SSI status 0.8.1
documents an older draft and cannot be assumed to implement the final Recommendation.

Sources:
- https://docs.rs/crate/ssi/0.16.0
- https://docs.rs/ssi-data-integrity-suites/0.4.0/ssi_data_integrity_suites/
- https://docs.rs/crate/sophia_c14n/0.10.0
- https://docs.rs/ssi-status/0.8.1/ssi_status/
- https://identity.foundation/well-known-did-configuration/resources/did-configuration/

## Milestones and acceptance gates

Each milestone's tests must pass before the next milestone starts. Maintain
`STATUS.md` with actual results and blockers. Test targets below are planned,
not claims that those tests already exist or have passed.

| Stage | Deliverable and acceptance | Validation |
|---|---|---|
| M0 | Pinned Cargo project, compliance matrix, real suite adapters, RDFC and suite vectors, base-proof validation, independent interoperation | `cargo check --locked --all-targets --all-features`; `cargo test --locked --test standards_vectors`; `bash scripts/interop.sh` |
| M1 | Complete CLI/help/config; typed models, schemas, reports; duplicate-property and JSON-LD data-loss rejection | `cargo test --locked --test cli_contract`; `cargo test --locked --test model_validation` |
| M2 | All key/suite/trust administration; Argon2id + XChaCha20-Poly1305 storage, safe atomic Linux files, rotation and fingerprint checks | `cargo test --locked --test key_storage`; `cargo test --locked --test key_rotation`; `cargo test --locked --test suite_and_trust` |
| M3 | did:web resolution, authorization, pinned offline contexts, SSRF/redirect/DNS/size/timeout protections | `cargo test --locked --test did_resolution`; `cargo test --locked --test resolver_security`; `cargo test --locked --test context_policy` |
| M4 | Issuance/verification/derivation/reissuance and signed revocation/suspension lists; no hidden-value leakage or active-on-network-failure | `cargo test --locked --test credential_workflows`; `cargo test --locked --test selective_disclosure`; `cargo test --locked --test credential_status` |
| M5 | Scoped policy/evidence decisions; signed and unsigned presentations; persistent atomic replay rejection | `cargo test --locked --test verification_policy`; `cargo test --locked --test evidence`; `cargo test --locked --test presentations` |
| M6 | Atomic public artefacts and full validation: DID, domain linkage, optional JWKS/OpenID, Holon metadata, manifest | `cargo test --locked --test well_known`; `cargo test --locked --test publication_rotation`; `cargo test --locked --test public_artifact_security` |
| M7 | Complete documentation/examples/security/deployment and all 14 end-to-end steps | final commands below |

## Interfaces and behavior

Separate cryptography, structure/schema validation, evidence, trust, and decision
calculation. Expose suite, resolver, context loader, replay store, evidence verifier,
and policy evaluator interfaces. Reports include stable per-stage errors and
passed/failed/unavailable/not-evaluated/not-applicable outcomes.

Configuration precedence: CLI, selected config, defaults. Holon status is required;
use explicit or configured lists. Revocation is permanent; restore only clears
suspension. Mandatory disclosure paths retain identity/type/issuer/validity/schema/
status metadata. Derivation cannot change signed schema references. Reissuance
uses the original issuer's authorized key and allocates a new ID and status entry.

`holon-assertion` is a policy scope, distinct from the `assertionMethod` proof purpose.
Unsigned presentations never authenticate holders. Signed presentations require
expected challenge/domain and authenticate holder control without assuming the
holder is the subject.

Confidence is an explicit non-statistical policy score: rejected/unverified/disputed
0; authentic 0.5; trusted 0.75; corroborated 1. Evidence download/digest checks do not
establish corroboration. Contradictory evidence is retained in disputed reports.

Exit codes: 0 success/accepted; 2 usage; 3 malformed input/config; 4 unsupported;
5 verification rejection/dispute; 6 insufficient trust; 7 unavailable dependency;
8 storage/security; 9 internal failure.

## Final validation

```sh
cargo fmt
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo build --locked --release
cargo test --locked --test end_to_end
cargo test --locked --test artifact_validation
bash scripts/run-documented-examples.sh
bash scripts/interop.sh
./target/release/holon-vc --help
./target/release/holon-vc help credential issue
./target/release/holon-vc presentation verify --help
./target/release/holon-vc --version
```

No completion claim with mocked cryptography, simulated selective disclosure,
ignored conformance failures, incomplete status/trust, or incomplete publication
validation. Report actual commands and results, patches, and interoperability limits.

## Completion record — 2026-09-28

M0–M7 implemented and acceptance gates passed for the supported Linux profile.
`STATUS.md` records exact final commands, results, repairs, and remaining external
interoperability/assurance limits. The complete suite has 42 passing tests; the
executable 14-step workflow performs 52 CLI operations with actual cryptography.

Clarifications made during implementation:

- Use `HolonSubjectSchema` for subject-level full/disclosure validation, explicitly
  distinguishing it from whole-VC W3C JSON Schema validation.
- Generated resource pins expire after five minutes; status pins also carry a
  retrieval timestamp checked against the signed TTL. Status force-refresh never
  resets allocations or revocations.
- Existing schema/context/profile limits fail explicitly; no fallback cryptography.
- The library can package up to 32 credentials; the CLI creates one-credential
  presentations. Verification checks every embedded credential.
- Per-file atomic writes plus manifest-last checking detect incomplete publication;
  a static server release-directory switch is recommended for snapshot deployment.
- Optional OpenID metadata documents an explicitly external service. The CLI does
  not claim to provide HTTP issuance endpoints.
- Independent security audit and broader ecosystem testing remain external assurance
  work, separate from the completed repository acceptance gates.

## Documentation kit follow-up — completed 2026-09-28

- Reused `.venv`, installed Zensical, and pinned its Python dependencies.
- Organized the existing `docs/` pages into an explicit searchable navigation.
- Added architecture/data-flow diagrams, a worked examples guide, and maintainer
  instructions. Example JSON is included from the actual repository fixtures.
- Added strict build/preview helpers and a separate `site-docs/` output directory.
- Passed strict build, Python dependency check, generated-link/anchor audit,
  local preview smoke check, and the 52-operation executable workflow.
