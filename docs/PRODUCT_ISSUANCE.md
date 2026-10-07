# Issue and publish the four product credentials

Use the output of the [shared product profile helper](PRODUCT_PROFILE_HELPER.md)
with the existing [GS1 Product issuer](GS1_PRODUCT_ISSUER.md). This walkthrough
assumes the issuer key, `issuer` suite, `products` status registry and target site's
GitHub Pages workflow already exist. Run commands in Bash on Linux. Python 3.11+
is sufficient; no extra Python packages are needed.

These are demonstration assertions by `did:web:gs1-product.perdl.com`, not evidence
of manufacturer endorsement or factual correctness. The existing product JSON-LD
values are preserved, including fictional-data statements. No reviews, ratings or
ingredient claims are added.

## 1. Retain the reviewed profile

Run from the `holon-vc` checkout:

```bash
set -euo pipefail
umask 077
cargo build --locked --release
HOLON_REPO="$PWD"
HOLON_BIN="$HOLON_REPO/target/release/holon-vc"
ISSUER_DATA="$HOME/.local/share/holon-vc/gs1-product"
ISSUER_SITE_REPO='/var/software/gitrepos/chris-day/gs1-product'
ISSUER_DID='did:web:gs1-product.perdl.com'
ISSUER_ORIGIN='https://gs1-product.perdl.com'
PROFILE_SOURCE="$HOLON_REPO/profiles/gs1-product-v1"
PRODUCT_PROFILE="$ISSUER_DATA/profiles/product-holon-v1"
PRODUCT_INPUTS="$ISSUER_DATA/product-inputs-v1"

# Alternatively set PROFILE_SOURCE to your reviewed helper output directory.
# Refuse to replace an existing profile used by previously issued credentials.
test ! -e "$PRODUCT_PROFILE"
mkdir -p "$(dirname "$PRODUCT_PROFILE")"
cp -R "$PROFILE_SOURCE" "$PRODUCT_PROFILE"
```

If the profile was already retained, reuse that directory and skip the last three
commands. Do not overwrite a published profile casually: preserve old versions
and choose a new profile identifier for incompatible changes.

## 2. Prepare unsigned Holons and pinned configuration

The former inline Python preparation block is now a repository script:

```bash
python3 "$HOLON_REPO/scripts/prepare_product_issuance.py" \
  --products-dir "$ISSUER_SITE_REPO/docs/products" \
  --profile-dir "$PRODUCT_PROFILE" \
  --issuer-did "$ISSUER_DID" \
  --origin "$ISSUER_ORIGIN" \
  --output "$PRODUCT_INPUTS"

PRODUCT_CONFIG="$PRODUCT_INPUTS/product-config.toml"
```

The output directory must be new. The script checks the complete product inventory,
source hashes, context and schemas against regenerated profile artifacts before
writing. If products changed, regenerate and review the shared profile first.
It creates:

- `product-config.toml`: absolute local paths and SHA-256 pins for the context and
  both schemas, under the profile ID
  `https://gs1-product.perdl.com/schemas/product-holon-v1`.
- `holons/GTIN.json`: one unsigned `ProductHolon` per product, with the original
  product object in `claims.product`. Only its root `@context` is removed; the
  shared scoped context supplies those same meanings.

The Holon ID is the site's product URL plus `#holon`; the original product ID
remains unchanged. `createdAt` records preparation time. `source` identifies the
issuer as a `demonstration-publisher`; evidence and related-Holons arrays are empty.
The helper currently supports root `did:web` issuers matching an HTTPS origin.
It does not sign, refresh status, edit the website or publish anything.

The context pin lasts 365 days from preparation. This is independent of credential
expiry and the five-minute DID/status pins. Keep the profile files at their
configured paths. Before the context pin expires, review and renew the local
configuration; changing a local pin does not extend signed credential validity.
For a later issuance batch, choose a new `PRODUCT_INPUTS` directory.

## 3. Refresh local issuer resources

Reuse the existing key and status registry; do not repeat key creation. Enter the
key password when prompted.

```bash
vc() {
  "$HOLON_BIN" --data-dir "$ISSUER_DATA" --offline --output-format json "$@"
}
vc well-known generate \
  --origin "$ISSUER_ORIGIN" --issuer-did "$ISSUER_DID" \
  --suite issuer --display-name 'GS1 Product — PERDL' --jwks --force
vc status create --id products \
  --url "$ISSUER_ORIGIN/status/products" --suite issuer --force
```

The status refresh preserves allocations, suspensions and revocations. Continue
promptly: generated local resource pins expire after five minutes. If issuance
reports `Pinned resource has expired`, refresh again before continuing; do not
weaken expiry checks.

## 4. Issue and verify each credential

```bash
mkdir -p "$ISSUER_DATA/credentials"
CREDENTIAL_EXPIRES="$(date -u -d '+365 days' '+%Y-%m-%dT%H:%M:%SZ')"
for gtin in 00083783000085 00195950643718 05000119096753 09506000134352
do
  vc --config "$PRODUCT_CONFIG" credential issue \
    --holon "$PRODUCT_INPUTS/holons/$gtin.json" \
    --schema-id 'https://gs1-product.perdl.com/schemas/product-holon-v1' \
    --suite issuer \
    --status-list "$ISSUER_DATA/status/products.json" \
    --expires "$CREDENTIAL_EXPIRES" \
    --output "$ISSUER_DATA/credentials/$gtin.vc.json"
  vc --config "$PRODUCT_CONFIG" credential verify \
    --credential "$ISSUER_DATA/credentials/$gtin.vc.json"
done
```

Each credential uses a real `eddsa-rdfc-2022` signature and gets status entries.
Each verification must exit zero with `cryptographicallyValid: true`,
`schemaValid: true`, and `status: "active"`. With no scoped trust policy,
`decision: "authentic-assertion"` and `issuerTrustedForClaimType: false` are expected.
An ordinal confidence of 0.5 is not a probability that product claims are true.

The expiry is 365 days from the command's execution, slightly less than 365 days
from subsequent issuance. Existing offer dates are not extended. This publishes
full credentials; it performs no selective disclosure.

Existing output files are not silently replaced. If a batch stops, inspect which
credentials succeeded and resume only the remaining GTINs. Replacement issuance
needs a deliberate decision about revoking the earlier credential and preserving
its audit record.

## 5. Stage public artifacts in the target repository

Run only after all four credentials verify:

```bash
PUBLIC="$ISSUER_SITE_REPO/issuer-public"
mkdir -p "$PUBLIC/contexts" "$PUBLIC/schemas"
cp "$PRODUCT_PROFILE/context.jsonld" "$PUBLIC/contexts/product-holon-v1.jsonld"
cp "$PRODUCT_PROFILE/schema.json" "$PUBLIC/schemas/product-holon-v1.json"
cp "$PRODUCT_PROFILE/disclosure.schema.json" "$PUBLIC/schemas/product-holon-v1-disclosure.json"
cp "$PRODUCT_PROFILE/NOTICE.txt" "$PUBLIC/schemas/product-holon-v1-NOTICE.txt"
for gtin in 00083783000085 00195950643718 05000119096753 09506000134352
do
  mkdir -p "$PUBLIC/products/$gtin"
  cp "$ISSUER_DATA/credentials/$gtin.vc.json" "$PUBLIC/products/$gtin/product.vc.json"
done
cp -R "$ISSUER_DATA/site/." "$PUBLIC/"
find "$PUBLIC" -type d -exec chmod 755 {} +
find "$PUBLIC" -type f -exec chmod 644 {} +
```

Keep the entire generated publication snapshot together: its manifest hashes must
match the exact bytes. Do not copy private keys, the private status registry,
configuration or the entire issuer data directory into the website repository.
The public status files are signed credentials, distinct from the private registry.

The schema's stable identifier ends in `/schemas/product-holon-v1`; this example
hosts the downloadable file at `/schemas/product-holon-v1.json`. They are distinct
URLs. The CLI uses the configured schema ID and local pins, not an automatic
schema download. Other verifiers need their own reviewed profile configuration.
Retain the Schema.org attribution notice with the published mappings.

## 6. Link credentials from the HTML product pages

The current target site uses standalone HTML templates with hard-coded
`<script id="product-data" type="application/ld+json">` blocks. Editing only
`docs/products/GTIN/index.md` or the JSON sidecar does not necessarily update those
blocks. The current template mapping is:

| Product GTIN | Template in the target repository |
| --- | --- |
| 00083783000085 — Sierra Nevada | `overrides/starlord-page-08.html` |
| 00195950643718 — Apple iPhone | `overrides/starlord-page-04.html` |
| 05000119096753 — Tesco jam | `overrides/starlord-page-12.html` |
| 09506000134352 — Dal Giardino rice | `overrides/starlord-page-00.html` |

Confirm each product index's `template:` frontmatter if the site's structure has
changed. Keep its existing product JSON-LD and visible facts consistent with the
sidecar used for issuance. A credential signs its own enclosed claims; a link does
not authenticate arbitrary other text on the page.

Add a section inside the template's main content. For the rice product:

```html
<section class="section" aria-labelledby="credential-heading">
  <div class="container">
    <h2 id="credential-heading">Signed product credential</h2>
    <p>This demonstration assertion is published by gs1-product.perdl.com.
      Its signature does not establish manufacturer endorsement or claim accuracy.</p>
    <p><a href="/products/09506000134352/product.vc.json">Download product credential (JSON)</a></p>
    <p><a href="/contexts/product-holon-v1.jsonld">Product context</a> ·
      <a href="/schemas/product-holon-v1.json">Product Holon schema</a></p>
  </div>
</section>
```

Use the corresponding GTIN in each other template. A download link is sufficient
and keeps the original product JSON-LD separate from the VC envelope. Do not show
an unconditional “verified” badge: verification also needs current status,
authorized keys, timestamps and the verifier's policy.

Optionally embed the complete issued credential in a **second**
`application/ld+json` script block with ID `product-credential`. Generate it from
the actual credential file at build time; never hand-author its proof or insert
placeholder signatures. When serializing for HTML, replace literal `<` with
`\u003c` to prevent a product value from closing the script element. Parsing the
embedded JSON must recover exactly the credential object. The commands here
publish download links; automatic embedding is not implemented by the helper.

## 7. Commit the source and let GitHub Pages deploy

The target site's workflow must run Zensical first, then overlay `issuer-public/`
onto `site/`, and upload `site/` including hidden files. Use the complete
[issuer integration workflow](GS1_PRODUCT_ISSUER.md#4-integrate-with-the-target-zensical-site).
Its essential order is:

```yaml
- run: zensical build --clean --strict
- run: cp -R issuer-public/. site/
- uses: actions/upload-pages-artifact@v5
  with:
    path: site
    include-hidden-files: true
```

This fragment belongs in the existing workflow before its deploy-pages step;
it is not a complete replacement workflow. The overlay publishes the credentials,
contexts and schemas as well as `.well-known` and status resources.

```bash
git -C "$ISSUER_SITE_REPO" add issuer-public \
  overrides/starlord-page-00.html overrides/starlord-page-04.html \
  overrides/starlord-page-08.html overrides/starlord-page-12.html
git -C "$ISSUER_SITE_REPO" diff --cached --stat
git -C "$ISSUER_SITE_REPO" commit -m "Publish signed product credentials and page links"
git -C "$ISSUER_SITE_REPO" push
```

Review staged files before committing. Do not check in generated `site/`.
Wait for the target site's Documentation action to succeed. GitHub Pages CDN
caching can temporarily expose old artifacts; wait for a consistent deployment
instead of bypassing manifest or signature checks.

## 8. Verify the deployed credentials

First repeat the issuer guide's HTTPS publication validation with the independently
retained issuer fingerprint. Then download and verify each published credential:

```bash
REMOTE_CHECK="$(mktemp -d /tmp/gs1-products-check.XXXXXX)"
for gtin in 00083783000085 00195950643718 05000119096753 09506000134352
do
  curl --fail --silent --show-error \
    "$ISSUER_ORIGIN/products/$gtin/product.vc.json" \
    --output "$REMOTE_CHECK/$gtin.vc.json"
  "$HOLON_BIN" --data-dir "$REMOTE_CHECK" \
    --config "$PRODUCT_CONFIG" --output-format json \
    credential verify --credential "$REMOTE_CHECK/$gtin.vc.json"
done
```

There is no `--offline` flag here: verification resolves the deployed DID and
status resources. Context and schema definitions still use the explicitly pinned
local configuration. Expect the same authentic-assertion/active results as local
verification. Open each product page and check its download link and original
product JSON-LD. When changing a signed claim, issue a new credential and update
the public artifact; editing a signed credential invalidates its proof.
