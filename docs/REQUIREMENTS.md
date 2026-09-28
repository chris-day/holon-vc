# Requirement-to-implementation map

The specification remains authoritative. This table points reviewers to concrete
implementation and validation. It is not a claim of external certification.

| Requirement | Implementation | Acceptance evidence |
|---|---|---|
| Complete CLI/config/errors/reports | cli, config, main, errors, reports | cli_contract; executable workflow; docs/CLI.md |
| Typed Holon/schema/source/evidence/relations | models, holon, schemas; paired JSON schemas | model_validation; credential_workflows |
| Ed25519/P-256 encrypted keys, export, rotation | keys, key_storage, public_keys, storage, app | key_storage; key_rotation; suite_and_trust |
| Modern RDFC EdDSA | canonicalization, suites | official_eddsa_and_legacy_signatures; standards_vectors; independent JS |
| Legacy verification and opt-in issuance | suites; suite validation and CLI flags | standards_vectors; credential_workflows; executable workflow |
| Genuine selective disclosure/base verification | disclosure with SSI selection, Sophia labels and RustCrypto | selective_disclosure; W3C canonicalization; independent nested cross-derivation |
| Issuer redacted reissuance/new identifier | credentials | executable workflow, canary absence and successful verification |
| Strict pinned JSON-LD and schemas | jsonld, canonicalization, schemas | context_policy; unknown/null terms; duplicate input tests |
| did:web/authorization/identity | did, resolvers | did_resolution; publication path and rotation tests |
| Scoped trust, freshness, evidence, conflicts | trust, evidence, verification | verification_policy; signed independent evidence and contradiction tests |
| Signed status/revoke/suspend/restore | status | credential_status; bit order; TTL; irreversible force refresh; full workflow |
| Signed/unsigned VP, holder/audience/replay | presentations; ReplayStore; SQLite | presentations; concurrent atomic consumption; reopened-store rejection |
| Public DID/linkage/JWKS/OpenID/metadata/manifest | well_known; publication JSON schemas | well_known; public_artifact_security; publication_rotation; artifact_validation |
| HTTPS/SSRF/DNS pinning/limits | resolvers | private address/offline tamper/stale tests; actual local HTTP negative fixtures |
| Safe Linux files/no secret logs | storage, key_storage, structured command diagnostics | symlink/permission/password tests; JSON output and secret-free errors |
| LLM trust/instruction boundary | evidence quarantine policy; documentation | instruction and policy tests; README and threat model |
| Documentation and 14-step workflow | README, SECURITY, docs, examples, scripts/workflow.py | end_to_end; run-documented-examples.sh; 52 CLI operations |

External limitations are explicit in docs/STANDARDS.md and SECURITY.md: application
VC2 linkage and subject-schema profiles, Linux storage, narrow VC/status/suite
profiles, no historical DID protocol or OpenID HTTP service, no security audit,
and per-file rather than multi-file atomicity. These are not simulated operations.

The original library gaps were SSI's base-proof verification and integration with
modern RDFC canonical label maps. Focused standards orchestration implements these
with real library primitives and independent interoperability checks. No remaining
required cryptographic operation is represented by a placeholder.
