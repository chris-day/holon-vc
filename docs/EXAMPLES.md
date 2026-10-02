# Examples and walkthrough

Run these commands from the repository root on Linux. The examples use real keys,
signatures, status lists and disclosure proofs. `issuer.example` is an offline
example identity, not a deployed service.

For the supplied Schema.org/GS1 product record, see the
[GS1 Risotto Rice example](Product-VC-example.md). It preserves the product
data, signs it with Ed25519 and P-256, and checks actual selective disclosure.

## Run the complete checked workflow

```sh
cargo build --locked --release
.venv/bin/python scripts/workflow.py
```

Expected final output:

```text
PASS: all 14 workflow steps; 52 CLI operations, real cryptography, replay rejection, redaction, rotation, revocation.
```

The workflow generates fresh random passwords, passes them on stdin, checks expected
exit codes and reports, then deletes its temporary directory. It covers setup,
publication, trust, status, modern/legacy/SD issuance, presentations, disclosure,
reissuance, suspension, revocation, administrative commands and rotation.

To inspect its outputs afterward, choose a directory that does not exist:

```sh
.venv/bin/python scripts/workflow.py --output /tmp/holon-vc-example-run
```

The retained output includes `holon.vc.json`, `selective.vc.json`, `derived.vc.json`,
`redacted.vc.json`, presentations, reports, and `data/site/`. Its generated password
is intentionally not exported, so these encrypted example keys cannot be reused.
The workflow ends with revocation and rotation; its final state is not a fresh
issuer setup. Use the interactive walkthrough below for reusable local keys.

## Input fixtures

The repository's `examples/holon.json` is the full input used by the workflow:

```json
--8<-- "examples/holon.json"
```

The reveal document selects statements using JSON pointers into the credential,
not pointers relative to the standalone Holon:

```json
--8<-- "examples/disclosure/reveal-document.json"
```

`name`, `value`, and `unit` are disclosed; `secret` is omitted from derived and
redacted outputs. ID/type/schema/status/validity metadata is retained. Additional
claim terms need an explicitly pinned context and paired schema profile; unknown
terms do not silently disappear.

The policy template in `examples/trust-policy.template.json` is intentionally not
an executable trust anchor until its fingerprint is replaced. The walkthrough uses
the actual generated public fingerprint instead.

## Interactive walkthrough

### 1. Create a private workspace and issuer key

These shell variables last for the current Bash session. Run the sequence in order.
The `vc` function calls the release binary using a dedicated offline data directory.
Each key operation prompts for a strong password; keep it if you want to reuse the keys.

```sh
export HOLON_EXAMPLE_DIR="$(mktemp -d /tmp/holon-vc-guide.XXXXXX)"
vc() {
  ./target/release/holon-vc \
    --data-dir "$HOLON_EXAMPLE_DIR/data" --offline --output-format json "$@"
}
vc key setup --id issuer --controller did:web:issuer.example
vc suite setup --name issuer \
  --key "$HOLON_EXAMPLE_DIR/data/keys/private/issuer.json" \
  --verification-method 'did:web:issuer.example#issuer'
```

### 2. Generate and validate public identity artifacts

```sh
vc well-known generate --origin https://issuer.example \
  --issuer-did did:web:issuer.example --suite issuer --jwks

ISSUER_FINGERPRINT="$(.venv/bin/python -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["fingerprint"])' \
  "$HOLON_EXAMPLE_DIR/data/keys/public/issuer.json")"

vc well-known validate --origin https://issuer.example \
  --issuer-did did:web:issuer.example \
  --expected-fingerprint "$ISSUER_FINGERPRINT" \
  --output-dir "$HOLON_EXAMPLE_DIR/data/site/.well-known"
```

Generated validated artifacts receive digest pins for offline resolution. The DID
key is authorized by those resources; issuer trust is still a separate choice.

### 3. Add scoped trust and create signed status lists

```sh
vc trust add --id issuer --issuer did:web:issuer.example \
  --verification-method 'did:web:issuer.example#issuer' \
  --fingerprint "$ISSUER_FINGERPRINT" \
  --credential-type HolonCredential --schema urn:holon:schema:1.0 \
  --purpose holon-assertion

vc status create --id main --url https://issuer.example/status/main --suite issuer
```

!!! tip "If you pause this walkthrough"
    Generated pins expire after five minutes. Refresh identity artifacts with the
    same `well-known generate` command plus `--force`, and refresh status lists with
    the same `status create` command plus `--force`. The status refresh preserves
    allocations and permanent revocations. Do not edit pin dates to bypass freshness.

### 4. Issue and verify an assertion

```sh
vc credential issue --holon examples/holon.json \
  --schema schemas/holon-v1.schema.json --suite issuer \
  --status-list "$HOLON_EXAMPLE_DIR/data/status/main.json" \
  --output "$HOLON_EXAMPLE_DIR/holon.vc.json"

vc credential verify --credential "$HOLON_EXAMPLE_DIR/holon.vc.json" \
  --threshold trusted-assertion --output "$HOLON_EXAMPLE_DIR/verification.json"
```

The expected decision is `trusted-assertion`, with valid cryptography, authenticated
issuer and `status: active`. Supporting evidence was not independently verified, so
this example does not claim corroboration or objective truth.

### 5. Create unsigned and signed presentations

```sh
vc presentation create --credential "$HOLON_EXAMPLE_DIR/holon.vc.json" \
  --output "$HOLON_EXAMPLE_DIR/unsigned.vp.json"
vc presentation verify --presentation "$HOLON_EXAMPLE_DIR/unsigned.vp.json"

vc suite setup --name holder \
  --key "$HOLON_EXAMPLE_DIR/data/keys/private/issuer.json" \
  --verification-method 'did:web:issuer.example#issuer' --purpose authentication

VERIFIER_CHALLENGE="$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(32))')"
vc presentation create --credential "$HOLON_EXAMPLE_DIR/holon.vc.json" \
  --holder did:web:issuer.example --suite holder --sign \
  --challenge "$VERIFIER_CHALLENGE" --domain verifier.example \
  --output "$HOLON_EXAMPLE_DIR/signed.vp.json"
vc presentation verify --presentation "$HOLON_EXAMPLE_DIR/signed.vp.json" \
  --challenge "$VERIFIER_CHALLENGE" --domain verifier.example
```

The unsigned result has `holderAuthenticated: false`; the fresh signed result has
`holderAuthenticated: true`. This local example uses the issuer's identity as the
holder to keep setup short. Real holders can have separate keys and DID documents.
The verifier, not the holder, must supply the challenge in a real exchange.

Repeating the signed verification intentionally returns exit **5** with `REPLAYED`.
Do not delete the replay database to make it pass; request a new verifier challenge.

### 6. Issue and derive genuine selective disclosure

```sh
vc key setup --id sd --algorithm p256 --controller did:web:issuer.example
vc suite setup --name sd --key "$HOLON_EXAMPLE_DIR/data/keys/private/sd.json" \
  --verification-method 'did:web:issuer.example#sd' --cryptosuite ecdsa-sd-2023

vc well-known generate --origin https://issuer.example \
  --issuer-did did:web:issuer.example --suite issuer --jwks --force

vc credential issue --holon examples/holon.json --suite sd \
  --status-list "$HOLON_EXAMPLE_DIR/data/status/main.json" \
  --output "$HOLON_EXAMPLE_DIR/selective.vc.json"
vc credential derive --credential "$HOLON_EXAMPLE_DIR/selective.vc.json" \
  --reveal examples/disclosure/reveal-document.json \
  --output "$HOLON_EXAMPLE_DIR/derived.vc.json"
vc credential verify --credential "$HOLON_EXAMPLE_DIR/derived.vc.json"
```

The derivation command needs no password or issuer key. The new P-256 verification
method has not been added to the trust store in this shorter walkthrough, so its
expected decision is `authentic-assertion`. The complete automated workflow also
adds scoped P-256 trust and checks `trusted-assertion`.

```sh
.venv/bin/python - "$HOLON_EXAMPLE_DIR/derived.vc.json" <<'PY'
import json, sys
credential = json.load(open(sys.argv[1]))
assert "secret" not in credential["credentialSubject"].get("claims", {})
assert "HIDDEN-CANARY" not in json.dumps(credential)
print("Hidden claim absent; verify the proof with credential verify.")
PY
```

Trying `credential derive` on the original Ed25519 credential fails explicitly.
A valid derived proof is not just JSON with some fields removed.

### 7. Reissue selected claims as the issuer

```sh
vc credential reissue-redacted --credential "$HOLON_EXAMPLE_DIR/holon.vc.json" \
  --reveal examples/disclosure/reveal-document.json --suite issuer \
  --status-list "$HOLON_EXAMPLE_DIR/data/status/main.json" \
  --output "$HOLON_EXAMPLE_DIR/redacted.vc.json"
vc credential verify --credential "$HOLON_EXAMPLE_DIR/redacted.vc.json"
```

This prompts for the original issuer's password. It produces a new credential ID
and status allocation, with a signed link back to the original. It is issuer
reissuance, not holder derivation.

### 8. Suspend, restore, and permanently revoke

```sh
vc status suspend --status-list "$HOLON_EXAMPLE_DIR/data/status/main.json" \
  --credential "$HOLON_EXAMPLE_DIR/holon.vc.json" --suite issuer
vc credential verify --credential "$HOLON_EXAMPLE_DIR/holon.vc.json"
```

Verification intentionally exits **5** and reports `suspended`.

```sh
vc status restore --status-list "$HOLON_EXAMPLE_DIR/data/status/main.json" \
  --credential "$HOLON_EXAMPLE_DIR/holon.vc.json" --suite issuer
vc credential verify --credential "$HOLON_EXAMPLE_DIR/holon.vc.json"
vc status revoke --status-list "$HOLON_EXAMPLE_DIR/data/status/main.json" \
  --credential "$HOLON_EXAMPLE_DIR/holon.vc.json" --suite issuer
vc credential verify --credential "$HOLON_EXAMPLE_DIR/holon.vc.json" \
  --output "$HOLON_EXAMPLE_DIR/revoked.report.json"
```

The restored credential is active. The final verification exits **5** and reports
`revoked`; the report is still written. Restoration cannot undo revocation.

## Other examples and validation

| Repository path | What it demonstrates |
|---|---|
| `examples/holon.json` | Typed claims, source and versioned subject |
| `examples/disclosure/reveal-document.json` | Subject-level statement selection |
| `examples/trust-policy.template.json` | Policy fields requiring a real fingerprint |
| `examples/public/public-key.json` | Public metadata from a disposable key |
| `examples/public/site/.well-known/` | Real signed public fixtures, including optional externally hosted OpenID metadata |
| `scripts/workflow.py` | The complete checked 52-operation CLI scenario |
| `interop/run.mjs` | Independent cryptographic interoperability checks |

The checked-in public fixtures have real signatures, but their dates and example
endpoints are not live deployment claims. Regenerate your own artifacts instead of
copying them into a production trust store.

```sh
cargo test --locked --test end_to_end
cargo test --locked --test artifact_validation
bash scripts/interop.sh
```

The interoperability script requires Node and its installed dependencies
(`npm ci --prefix interop`). See the [CLI reference](CLI.md) for legacy opt-in,
key rotation, detailed flags, and inspection commands, and
[issuer deployment](DEPLOYMENT.md) before publishing public files.
