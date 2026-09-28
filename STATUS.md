# Implementation status

## Current result

Implemented M0–M7 for the documented Linux Holon profile. All repository acceptance
gates have passed. Real cryptography and genuine selective disclosure are used;
there are no mocked cryptographic operations or unimplemented CLI branches.
This is a tested implementation candidate, **not an independently audited or
certified production system**. External interoperability/profile limits are below.

Final validation date: 2026-09-28. Workspace: `/var/software/gitrepos/holon-vc`.
The authoritative specification was read completely and was not modified.
No external deployment, message, Git commit, or push was performed.

## Milestones and durable decisions

| Milestone | Result | Evidence |
|---|---|---|
| M0 cryptographic foundation | PASS | 84 applicable official SHA-256 RDFC cases; exact W3C modern/legacy signatures; independent bidirectional JS interoperation for all three suites |
| M1 CLI/models/schemas/reports | PASS | Every help path; strict duplicate-property parsing; typed Holons; schema tests; machine/human output and exit contracts |
| M2 encrypted keys/suites/trust administration | PASS | Argon2id + XChaCha20-Poly1305, wrong passwords, metadata tampering, permissions, symlinks, rotation, legacy opt-in and scoped policy validation |
| M3 DID/contexts/resolution | PASS | Origin/path DID translation, relationship authorization, pinned contexts, stale/tampered pins, prohibited IPs, actual local HTTP negative fixtures |
| M4 credentials/disclosure/status | PASS | Modern/legacy issuance; tamper/date/null/undefined-term rejection; genuine derivation and canary non-disclosure; issuer reissuance; all status transitions; MSB bit ordering; cache TTL |
| M5 policy/evidence/presentations | PASS | Scoped trust/quarantine, digest-only non-corroboration, independent signed evidence, contradictions, signed/unsigned VPs, nonce/domain checks, concurrent and persistent replay rejection |
| M6 publication | PASS | Origin/path layout; signed linkage; DID/JWKS agreement; rotation; schema validation; stale/tampered/private-field rejection; golden shapes for every public artefact, including OpenID metadata |
| M7 docs and end-to-end acceptance | PASS | Full 14-step workflow plus administration and negative checks: 52 real CLI operations; release-binary workflow; README, full CLI reference, configuration/deployment/security/threat-model docs and examples |

Key decisions and repairs:

- SSI's missing ECDSA-SD base-proof validation and older canonicalization integration
  were addressed by a focused standards adapter: SSI JSON-LD selection, Sophia
  RDFC labels, RustCrypto P-256/HMAC/SHA-256, and ed25519-dalek. No cryptographic
  primitives were invented or replaced with simulations. Unused umbrella SSI
  dependencies were removed; required direct crates and lockfiles are pinned.
- Sophia's default parser relabeling initially broke canonical label maps. Preserving
  blank-node labels fixed the official mapping vectors. Resource-exhausting graphs
  fail closed; SHA-384 cases are outside the supported Ed25519/P-256 profile.
- Protected JSON-LD term collisions and the missing subject-level evidence mapping
  were found by issuance/workflow tests and repaired without relaxing expansion.
- `HolonSubjectSchema` is an explicit application-specific subject schema profile,
  with pinned full/disclosure variants. It does not masquerade as whole-VC JSON Schema.
- Status lists are signed Bitstring Status List 1.0 revocation/suspension lists.
  Force-refresh preserves allocations and irreversible revocations. Cached status
  requires a retrieval timestamp and cannot exceed its signed TTL even if the
  configured pin expiry is later. Unavailable/unverifiable status never means active.
- Holder authentication is false after challenge/domain mismatch or replay rejection,
  while signature validity remains a separate result.
- Resource pins never install issuer trust. Digest evidence alone never establishes
  corroboration. Independent-source grouping and equality comparisons are explicit policy.
- Publication uses atomic files and manifest-last consistency detection. Deployment
  documentation explains snapshot publication and multi-file crash-recovery limits.

## Exact final verification

All commands below returned exit code **0**.

| Command | Result |
|---|---|
| `cargo fmt` | PASS |
| `cargo fmt --check` | PASS; no formatting differences |
| `cargo check --locked --all-targets --all-features` | PASS |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | PASS; no Clippy warnings |
| `cargo test --locked --all-features` | **42 passed, 0 failed, 0 ignored**, across 20 integration-test targets; unit/doc-test targets also pass |
| `cargo test --locked --test end_to_end` | PASS; all 14 steps and 52 CLI operations |
| `cargo test --locked --test artifact_validation` | PASS; publication golden shapes, schemas, original fixture signature, private-field checks |
| `cargo build --locked --release` | PASS; `target/release/holon-vc`, version 0.1.0 |
| `bash scripts/run-documented-examples.sh` | PASS against release binary: all 14 steps, 52 CLI operations |
| `bash scripts/interop.sh` | PASS; Rust→JS and JS→Rust modern EdDSA, legacy Ed25519, ECDSA-SD, including nested cross-derived proofs |
| `./target/release/holon-vc --help` | PASS |
| `./target/release/holon-vc help credential issue` | PASS |
| `./target/release/holon-vc presentation verify --help` | PASS |
| `./target/release/holon-vc --version` | PASS; `holon-vc 0.1.0` |
| `git diff --check` | PASS |

An additional inspection parsed all seven public example JSON files and found no
private-key fields. Public examples contain actual signatures from a disposable
in-memory key. Their dates/endpoint URLs are fixtures, not live trust anchors or services.

Environment notes: rustfmt and Clippy were initially absent and were installed.
The sandbox denied local HTTP fixture sockets, so resolver/full tests ran with the
approved socket permission. Node child-process execution had stalled in the sandbox;
the independent interop script ran with approved execution outside it. Some builds
emit dependency-cache diagnostics (`unable to cache regular automaton: Read-only
file system`); those are cache-write messages, not compiler/Clippy failures.
A server restart interrupted the final pass; repository state was checked and the
final tests/build/checks were rerun successfully afterward.

## Remaining interoperability and assurance limits

1. The approved VC2 domain-linkage profile is application-specific. It is not the
   established DIF VC1 `issuanceDate`/`expirationDate` profile. Holon subject schema
   validation is also an explicit application profile.
2. Supported VC profile: one proof, one subject, string did:web issuer, required
   validity/schema/status metadata. No JWT VC, SD-JWT, BBS, proof chains, multi-bit
   status messages, arbitrary contexts, or historical DID resolution is advertised.
3. Legacy cryptographic interoperability passes. Compatibility with every legacy
   wallet's VC1 shape and DID verification-key-class expectations is not claimed.
4. OpenID publication describes explicitly configured external services. This CLI
   implements no OAuth/OpenID issuance HTTP server and cannot certify those endpoints.
5. Linux filesystem support; no Windows port or HSM integration. SQLite replay and
   private storage assume an owner-controlled OS account. Rotation/publication are
   not one multi-file transaction; documented backup/recovery/deployment steps apply.
6. Disclosure remains correlatable through mandatory identifiers/status/timestamps.
   Source independence is configured, confidence is ordinal, and quarantine is only
   a heuristic. Authentic or corroborated assertions are never declared objective truth.
7. Independent security review of the cryptographic orchestration and the application
   remains outstanding. No audit, certification, universal ecosystem interoperability,
   or production-readiness claim is made.

See `docs/REQUIREMENTS.md`, `docs/STANDARDS.md`, `SECURITY.md`, and
`docs/THREAT_MODEL.md` for the implementation map and detailed limits.

## Documentation kit — 2026-09-28

Installed Zensical 0.0.65 and its Markdown/rendering dependencies into the existing
Python 3.14 `.venv`. `requirements-docs.in` records the direct dependency;
`requirements-docs.txt` pins the installed dependency set. Python tooling and
build output are ignored by Git.

Added `zensical.toml`, the documentation homepage, `docs/ARCHITECTURE.md` with
three Mermaid diagrams, `docs/EXAMPLES.md` with runnable commands and included
source JSON fixtures, and `docs/DOCUMENTATION.md` with build/preview/maintenance
instructions. All six existing reference documents remain part of the site.
`scripts/docs.sh` builds or serves the kit. Output is `site-docs/`, separate from
issuer public artifacts. A small 404 template fixes the theme's missing skip anchor.

Verification:

- `bash scripts/docs.sh build`: PASS; clean strict Zensical build, no issues.
- `.venv/bin/python -m pip check`: PASS; no broken requirements.
- Generated HTML audit: PASS; 11 pages, local page/asset links and anchors,
  three Mermaid blocks, rendered source JSON snippets and nonempty search index.
- `.venv/bin/python scripts/workflow.py`: PASS; 14 steps and 52 CLI operations.
- Local preview smoke check: PASS; HTTP 200 for home, architecture, examples and
  search index. Loopback permission was required after a sandbox socket denial;
  the temporary preview server was stopped after checking.
- `bash -n scripts/docs.sh` and `git diff --check`: PASS.

No documentation deployment was performed. Set an actual `project.site_url` in
`zensical.toml` before public deployment when canonical URLs/sitemap are needed.
The kit uses no fabricated production URL. No Rust behavior was changed for this task.

## GitHub Pages workflow — 2026-09-28

Added `.github/workflows/docs.yml`: pull requests to `main` build the docs; pushes
to `main` and manual runs on `main` build and deploy `site-docs/` using the official
GitHub Pages actions. Python 3.14 installs `requirements-docs.txt` in a fresh `.venv`
and runs the existing strict build helper. Deployment has separate Pages/OIDC
permissions, a `github-pages` environment and serialized deployment concurrency.

Set `project.site_url` to `https://chris-day.github.io/holon-vc/`, superseding the
earlier unset-URL guidance. Documented the one-time Settings → Pages → GitHub
Actions selection and manual run instructions in `docs/DOCUMENTATION.md`.

Verification:

- `bash scripts/docs.sh build`: PASS, exit 0; no issues found.
- `.venv/bin/python -m pip check`: PASS, exit 0; no broken requirements.
- Local YAML/structure checks: PASS; triggers, deployment gates, permissions,
  dependency between jobs and artifact path checked. Embedded shell syntax passes
  `bash -n`. This is local validation, not a GitHub-hosted workflow execution.
- Generated canonical URL and sitemap: PASS; include the `/holon-vc/` project path.
  The initial audit expected a directory-style homepage; corrected that assertion
  to `index.html` to match the existing file-style URL configuration.
- `git diff --check`: PASS.

The workflow has not been pushed or run on GitHub, and repository Pages settings
have not been changed. Remote publication requires committing/pushing these files
and enabling GitHub Actions as the Pages source. No Rust behavior changed.
