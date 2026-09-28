# Holon VC documentation

Issue, selectively disclose, present, and verify **attributed Holon assertions**
with a Rust library and CLI.
{ .lead }

Holon VC separates signature validity, DID authorization, issuer trust, credential
status, and supporting evidence. A valid signature authenticates an assertion;
it does not establish that the assertion is true.

[Run the examples](EXAMPLES.md){ .md-button .md-button--primary }
[Explore the architecture](ARCHITECTURE.md){ .md-button }

## Choose a starting point

| Task | Read |
|---|---|
| Run the complete workflow or issue your first credential | [Examples and walkthrough](EXAMPLES.md) |
| Understand the modules, data flow, and security boundaries | [Architecture](ARCHITECTURE.md) |
| Find a command or flag | [CLI reference](CLI.md) |
| Configure suites, status lists, schemas, or offline resources | [Configuration](CONFIGURATION.md) |
| Publish issuer DID and discovery artifacts over HTTPS | [Issuer deployment](DEPLOYMENT.md) |
| Assess compatibility and security assumptions | [Standards](STANDARDS.md) and [threat model](THREAT_MODEL.md) |
| Build, preview, or extend this documentation | [Documentation kit](DOCUMENTATION.md) |

## What is implemented

- Encrypted Ed25519 and P-256 keys, suite bindings, public export, and rotation.
- VC 2.0 Holon issuance using modern EdDSA, with explicit legacy issuance support.
- Genuine ECDSA-SD selective disclosure and issuer-controlled redacted reissuance.
- Signed and unsigned presentations, expected challenge/domain checks, and
  persistent replay protection.
- Scoped issuer policies, explicit evidence comparisons, and signed revocation
  and suspension lists.
- DID, domain linkage, optional JWKS/OpenID metadata, Holon metadata, and manifests.

## Read a verification result

| Decision | Interpretation |
|---|---|
| `authentic-assertion` | Required cryptographic, authorization, schema, validity, and status checks pass |
| `trusted-assertion` | The authentic assertion also meets a scoped local issuer policy |
| `corroborated` | Explicit policy comparisons find matching signed evidence from configured independent sources |
| `unverified` | Required information or evidence is unavailable or insufficient |
| `disputed` | Authenticated claims or evidence contradict the configured comparison |
| `rejected` | A required validation or policy constraint fails |

Always inspect stage results, warnings, and nested reports. Confidence scores are
ordinal policy levels, not probabilities. Treat every credential's text as data,
including when a trusted issuer supplied it.

!!! note "Supported profile and assurance"
    This is a tested Linux implementation candidate, not an independently audited
    product. Domain linkage and subject-schema validation use explicit application
    profiles. OpenID metadata describes external services; the CLI does not operate
    an issuance HTTP server. Read the [interoperability boundaries](STANDARDS.md#application-interoperability-boundaries).

The repository's `Holon_VC_Implementation_Prompt_v1.0.0.md` is the authoritative
specification. `PLAN.md` and `STATUS.md` record implementation decisions and exact
verification results; the [requirements map](REQUIREMENTS.md) connects them to code
and tests.
