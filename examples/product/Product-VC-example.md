# GS1 Risotto Rice

This runnable example uses the supplied Dal Giardino product JSON-LD, including
its GS1 Digital Link identity, nested offer, shipping and return information,
reviews, ratings, ingredients and allergen statement. It makes real signatures
under the offline demonstration DID `did:web:product-issuer.example`. It does not
represent a credential issued or endorsed by Dal Giardino, GS1, or the reviewers.

## Prerequisites and checkout

Use Linux and Bash, Rust 1.92 or later with Cargo, Python 3.11 or later, and Git.
The project has been validated with Rust 1.92 and Python 3.14. Initial dependency
installation/build needs internet access; the credential exercises run offline.
No web server, domain ownership, paid service, `jq`, or Python crypto package is
required for this local demonstration.

For a new checkout:

```sh
git clone https://github.com/chris-day/holon-vc.git
cd holon-vc
```

If you already have the repository, open a terminal in its root instead. Check
that `cargo --version` and `python3 --version` succeed. Create the documentation
virtual environment only if it does not already exist:

```sh
if [ ! -x .venv/bin/python ]; then python3 -m venv .venv; fi
.venv/bin/python -m pip install -r requirements-docs.txt
```

Choose either the automated route below or the manual walkthrough. Each creates
its own isolated runtime directory. Commands require the example files from this
revision of the repository.

## Automated route

From the repository root on Linux:

```sh
cargo build --locked --release
.venv/bin/python scripts/product-workflow.py --output /tmp/holon-product-example
```

The output directory must not already exist. Omit `--output` to run all checks
in a temporary directory and remove the outputs afterward. The workflow uses
Python's standard library; it requires no additional Python packages.

Expected result:

```text
PASS: 17 CLI operations; full Ed25519/P-256 credentials, three tamper rejections, real selective disclosure, product preservation and HTML embedding.
```

| Output | Purpose |
| --- | --- |
| `product.holon.json` | The supplied product inside a Holon record |
| `issuer.vc.json` | Complete VC with a real `eddsa-rdfc-2022` proof |
| `selective.vc.json` | Complete VC with a real `ecdsa-sd-2023` base proof |
| `derived.vc.json` | Verifiable disclosure of identity, ingredients and allergens |
| `issuer.report.json`, `selective.report.json`, `derived.report.json` | Verification results at generation time |
| `product.html` | Minimal page embedding the exact issued Ed25519 credential |
| `config.toml` | Generated context and schema pins using absolute local paths |
| `data/` | Private keys, local policies, status registry, and staged public resources |
| `tampered-*.json` | Deliberately invalid credentials used for rejection checks |

Do not publish the entire output directory. The workflow generates a random
password and never retains it, so retained private keys are not reusable after
the run. This example is intended to be regenerated. Generated DID/status pins
expire after five minutes; the credentials and context pin expire after one day.
Saved reports are observations at generation time, not continuing verification.

To repeat verification immediately after the run:

```sh
target/release/holon-vc \
  --data-dir /tmp/holon-product-example/data \
  --config /tmp/holon-product-example/config.toml \
  --offline --output-format json \
  credential verify \
  --credential /tmp/holon-product-example/issuer.vc.json \
  --threshold trusted-assertion
```

## Supplied product JSON-LD

The entire source is included directly from the executable example fixture:

```json
--8<-- "examples/product/product.jsonld"
```

## Manual walkthrough: every command

The blocks below are included from `examples/product/walkthrough.sh`, so the
published commands and the runnable version remain identical. Alternatively, run
`bash examples/product/walkthrough.sh` from the repository root and answer its
password prompt. It leaves artifacts in the directory printed at startup.

### 1. Build and choose a private workspace

Run all following blocks **in order in the same Bash session**, starting in the
repository root. `mktemp` chooses a new directory for every run. Choose a nonempty
password when prompted and retain it if you want to reuse these manual-run keys.
The password stays in a shell variable and is passed over stdin, never in command
arguments. Do not run the walkthrough with shell tracing (`set -x`).

```bash
--8<-- "examples/product/walkthrough.sh:setup"
```

### 2. Prepare the Holon and pinned configuration

This copies every supplied product value into `claims.product` and generates
actual SHA-256 pins, absolute paths, creation time and a one-day expiry. No
placeholder substitution is necessary. The input's inline context is represented
by the scoped, pinned context distributed with this example.

```bash
--8<-- "examples/product/walkthrough.sh:prepare"
```

### 3. Create keys, suites and local trust policies

These commands create two encrypted keys, associate them with their cryptosuites,
and read the actual public-key fingerprints to configure local trust. This trust
is explicitly granted for the demonstration; it does not establish brand ownership.

```bash
--8<-- "examples/product/walkthrough.sh:keys"
```

### 4. Stage DID metadata and signed status lists

Both keys are created before staging the DID so it authorizes both verification
methods. These commands create local public artifacts and resource pins. They do
not upload anything or attempt to resolve the `.example` domain over the network.

Complete steps 5–7 within five minutes of this step. If you pause longer, use the
refresh commands below before continuing.

```bash
--8<-- "examples/product/walkthrough.sh:publish"
```

### 5. Issue and verify both full credentials

Each command must exit successfully. The verification reports should contain
`"cryptographicallyValid": true`, `"status": "active"`, and
`"decision": "trusted-assertion"`. The subject schema is this example's configured
product schema, not the bundled temperature-example schema.

```bash
--8<-- "examples/product/walkthrough.sh:issue"
```

### 6. Derive and verify the reduced credential

Derivation uses the P-256 credential, and requires no signing password. The
assertions below check successful verification and confirm that offers, reviews,
aggregate ratings and SKU were omitted.

```bash
--8<-- "examples/product/walkthrough.sh:derive"
```

### 7. Confirm that changing a signed price fails

A verification failure is the **expected success condition** here. The block
requires exit code 5 and a failed cryptographic check, so an unrelated error does
not count as a successful tamper test.

```bash
--8<-- "examples/product/walkthrough.sh:tamper"
```

### 8. Embed the issued credential in HTML

This writes an actual HTML page with the complete signed credential. Its visible
product JSON is generated from the same credential. Open the printed file path
in your browser. The password variable is cleared after this step.

```bash
--8<-- "examples/product/walkthrough.sh:html"
```

### Refresh resources after a pause

For the **manual** walkthrough, reuse the same shell variables and password. If
step 8 cleared the variable, read your original password again:

```bash
read -r -s -p 'Original demonstration key password: ' PRODUCT_PASSWORD
printf '\n'
sign_vc well-known generate --origin https://product-issuer.example \
  --issuer-did "$PRODUCT_DID" --suite issuer --force
sign_vc status create --id products \
  --url https://product-issuer.example/status/products --suite issuer --force
vc credential verify --credential "$PRODUCT_RUN/issuer.vc.json" \
  --threshold trusted-assertion
unset PRODUCT_PASSWORD
```

Status refresh preserves existing allocations and revocations. It does not extend
the credential or context's one-day expiry. After a day, start a fresh walkthrough.
For the **automated** route, the random password is not retained: rerun it into a
new directory instead.

### Troubleshooting

| Symptom | Action |
| --- | --- |
| Automated `--output` directory already exists | Select a new directory; existing artifacts are never overwritten automatically. |
| Expired resource/status pin | Refresh the manual run as above, or regenerate the automated run. |
| Wrong key password | Use the password entered in manual step 1. Automated passwords are intentionally not retained. |
| Unknown context or missing schema | Pass the generated `config.toml` using the `vc` wrapper; do not issue with the default schema. |
| `trusted-assertion` threshold is not met | Complete step 3 with the actual generated fingerprints and the same data directory. |
| Output file already exists when repeating a step | Start a fresh walkthrough, or deliberately use the command's `--force` option for an output you intend to replace. |

Keep `data/` private. Only selectively publish the credential and HTML files;
private keys, local trust policies and the status registry are not website files.
The staged public DID/status resources need their own deliberate deployment for
an online issuer. This walkthrough is fully local.

## Build and preview this guide

```sh
bash scripts/docs.sh build
bash scripts/docs.sh serve
```

Open `http://127.0.0.1:8000/Product-VC-example.html`; stop the preview with Ctrl-C.
The static build is in `site-docs/Product-VC-example.html`.

## What gets signed

The layout is:

```text
VerifiableCredential + HolonCredential
  issuer: did:web:product-issuer.example
  credentialSubject:
    id: urn:example:holon:product:09506000134352
    type: ProductHolon
    schemaVersion: 1.0
    createdAt: actual generation timestamp
    claims:
      product: the supplied product object
  credentialSchema: product Holon subject schema
  credentialStatus: revocation and suspension entries
  proof: generated Data Integrity proof
```

`examples/product/product.jsonld` preserves the supplied standalone JSON-LD.
The workflow copies its product properties without changing their values; only
the top-level `@context` is relocated into a pinned, scoped context. The original
product ID remains `https://id.gs1.org/01/09506000134352`. The Holon record and
the generated credential have separate identifiers.

`examples/product/context.jsonld` extends the built-in Holon context and scopes
the product terms to `claims.product`. Its Schema.org term definitions are a
subset of the [official context](https://schema.org/docs/jsonldcontext.json),
retrieved 2026-09-28. That context maps terms to **`http://schema.org/`** IRIs;
these mappings are preserved even though the context URL is HTTPS. The supplied
GS1 prefix remains **`https://gs1.org/voc/`**. In particular, the product's
`value` is Schema.org's value, not the temperature example's Holon value.
The approach uses standard [JSON-LD scoped contexts](https://www.w3.org/TR/json-ld11/#scoped-contexts).

The context deliberately contains only terms needed by this example. New product
fields require an explicit context/schema update. Both full and disclosure schemas
are local, pinned, self-contained subject schemas. They validate the example's
structure and field types; they are not a GS1 certification schema and do not
establish the accuracy, ownership, regulatory compliance, or current commercial
validity of the claims. In particular, `priceValidUntil` is a product claim;
credential validity checking does not independently enforce that offer date.

## Applying the result to ExampleHolon.html

Replace the previous credential script with the **complete** contents of
`issuer.vc.json`, not an independently assembled proof:

```html
<script id="product-credential" type="application/ld+json">
  <!-- Insert HTML-safe serialization of the entire generated VC here. -->
</script>
```

The snippet above is a template, not valid credential JSON. `product.html`
demonstrates actual insertion: serialize the credential as JSON and escape `<`
as `\u003c` so product strings cannot terminate the script element. Do not HTML
entity-escape JSON quotes. Escaping must preserve the parsed credential object.

Read the visible product fields from
`credentialSubject.claims.product`; read issuer, validity and proof information
from the generated VC. Do not edit signed fields after issuance. The signature
covers the credential data, not surrounding HTML or the bytes of linked images.
The generated page explicitly states that it performs no live verification.

For a real deployment, configure an issuer identity and key controlled by the
publisher, host its DID and signed status lists, distribute the pinned context
and schemas, and establish verifier trust independently. The example's local
trust policy deliberately trusts the fresh demonstration key; a
`trusted-assertion` result is scoped to that policy. The `.example` domain and
URN profile identifiers here are not a public deployment.

## Actual selective disclosure

The workflow separately issues a P-256 `ecdsa-sd-2023` credential and derives a
credential retaining the product ID, types, name, GTINs, ingredients and allergens.
Offers, reviews, aggregate ratings and SKU are absent. The normal mandatory VC
and Holon identifiers, issuer, validity, schema and status metadata remain.

The selection is maintained in `examples/product/reveal.json`. The derived
credential verifies without signing again or supplying the issuer's private key.
It remains correlatable through its mandatory identifiers. Ed25519 credentials
cannot be selectively disclosed this way by deleting properties.

The automated workflow’s three negative checks change price, ingredient text and a review after
issuance, and require cryptographic rejection. No unsigned placeholder or mock
signature is used. The original product assertions, including reviews and offers,
are all attributed to this demonstration publisher; there is no claim that the
named reviewers independently signed them or that this is corroborated evidence.

## Example files and code reference

The documentation source is `examples/product/Product-VC-example.md`. The site
page `docs/Product-VC-example.md` includes it directly. Edit this source when
changing the example; the command snippets and product JSON are also included
from their actual files rather than maintained as separate copies.

| File | Role |
| --- | --- |
| `examples/product/product.jsonld` | Complete standalone Schema.org/GS1 product input, without a VC envelope or proof. |
| `examples/product/context.jsonld` | Holon extension and scoped product vocabulary used during RDF processing and signing. |
| `examples/product/schema.json` | Full subject schema required for issuance and verification of the complete product. |
| `examples/product/disclosure.schema.json` | Subject schema for the reduced, derived credential. |
| `examples/product/reveal.json` | Seven explicit JSON Pointer selections for disclosure. |
| `examples/product/walkthrough.sh` | Interactive Bash implementation of the eight manual steps above. |
| `scripts/product-workflow.py` | Automated issuance, verification, negative checks, disclosure and HTML generation. |
| `tests/product_example.rs` | Cargo integration test that executes the automated workflow against the test-built CLI. |

### Context and identifiers

`context.jsonld` first includes `urn:holon:context:1.0`, then defines
`ProductHolon` as `urn:example:ProductHolon` and `product` as
`urn:example:product`. The `product` property supplies its own scoped context.
Within that scope, `id` and `type` alias `@id` and `@type`; the supplied product
classes and properties map to Schema.org, and `gs1:` expands using the supplied
GS1 namespace. The full context is:

```json
--8<-- "examples/product/context.jsonld"
```

The document passed for issuance contains only the approved context URL. Inline
term definitions live inside the trusted, pinned context file. The example does
not disable the CLI's rejection of inline contexts in input credentials.

### Full and disclosure schema behavior

Both schemas use Draft 2020-12 and the same ID,
`urn:example:product-holon:1.0`, because the signed credential identifies one
profile with full and disclosure variants. They validate `credentialSubject`.

| Constraint | Full schema | Disclosure schema |
| --- | --- | --- |
| Required Holon fields | `id`, `type`, `schemaVersion`, `claims`, `createdAt` | `id`, `type`, `schemaVersion`, `claims` |
| Holon type/version | `ProductHolon` / `1.0` | Same |
| Required claims | `product` | `product` |
| Required product fields | Every property present in the supplied product | `id`, `type`, `name`, `gtin14` |
| Required nested object fields | All supplied fields in each nested object | Nested fields become optional |
| Unknown object properties | Rejected | Rejected |
| GTIN strings | Exactly 14 decimal digits | Same when present |
| Product arrays | Nonempty arrays with typed items | Same when present |

The schemas retain types and constraints on disclosed values. Product strings
must be nonempty and quantities are JSON numbers. The schemas do not verify a
GTIN check digit, require both GTIN properties to agree, recompute review averages,
or constrain every number to an integer or positive range. Product date strings
are not checked as commercial expiry rules. Holon URI/date fields have their
own format constraints. These are example profiles, not full GS1 business-rule
validation. Optional evidence and related-Holon shapes are inherited from the
Holon profile; both workflows supply empty arrays and make no corroboration claim.

### Reveal selection

```json
--8<-- "examples/product/reveal.json"
```

These seven pointers retain product identity, name, GTINs, ingredients and
allergens. The CLI additionally retains mandatory credential/Holon metadata.
The disclosure schema requires product `id`, `type`, `name` and `gtin14`, so a
new reveal selection must still satisfy that profile. Adding a pointer does not
add a claim to the source credential; the selected claim must already be signed.

### Manual shell implementation

The `setup` section enables shell error handling, sets owner-only output
permissions and creates a fresh working directory. `vc()` supplies the same
binary, data directory, pinned configuration, offline mode and JSON output to
every command. `sign_vc()` adds password input over stdin only where required.
The remaining named snippet sections prepare files, configure keys and trust,
stage public resources, issue, derive, perform a price-tamper check and build HTML.

`issuer-key.json` and `selective-key.json` contain public setup reports used for
fingerprint extraction; encrypted private keys live under `data/keys/private/`.
`expires.txt` carries the generated one-day expiry into the issuance commands.
The script leaves its artifacts in the printed directory. It checks one tampered
price; the automated runner additionally checks ingredients and review text.

### Automated Python implementation

`main()` accepts `--binary` (default `target/release/holon-vc`) and `--output`
(a new directory). Without `--output`, a temporary directory is cleaned up after
success. It generates an ephemeral password and one-day expiry. `digest()` hashes
context/schema bytes, `write()` serializes output JSON, and `run()` invokes the
CLI with fixed offline/configuration arguments, a 90-second timeout per command,
expected exit-code checking and JSON response parsing.

The 17 CLI operations comprise six key/suite/trust operations, two publication
and status operations, four full issuance/verification operations, three negative
verification operations and two disclosure/verification operations. The runner
also compares both full credential product objects with the input, checks the
derived product's required claims and omissions, and round-trips HTML-safe JSON.
It never implements signing itself: cryptography is performed by the Rust CLI.

### Regression check and maintenance

```sh
cargo test --locked --test product_example
bash -n examples/product/walkthrough.sh
bash scripts/docs.sh build
```

The Rust test starts `python3 scripts/product-workflow.py --binary` with Cargo's
built CLI path and requires successful completion. It tests the automated route;
it does not execute the interactive Bash script. Run the manual route separately
when changing its commands. Keep the schema, context and reveal selection aligned
when adding product fields; regenerate the runtime configuration to pin the new
file digests. Never edit already signed credentials to update claims.

