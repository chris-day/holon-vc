# Generate a shared product profile

`scripts/product_profile.py` recursively finds `product.jsonld` files beneath
`docs/products` and builds a shared context and Holon subject schema. It reads
product data without editing files, coercing values or adding claims. The new
profile identifier is:

```text
https://gs1-product.perdl.com/schemas/product-holon-v1
```

The matching context identifier is:

```text
https://gs1-product.perdl.com/contexts/product-holon-v1.jsonld
```

## Generate from your website checkout

Run from the `holon-vc` repository with Python 3.11 or later. No extra Python
packages or network access are required; the official Schema.org context snapshot
is bundled with provenance and its SHA-256 digest.

```bash
python3 scripts/product_profile.py \
  --products-dir /var/software/gitrepos/chris-day/gs1-product/docs/products \
  --profile-id https://gs1-product.perdl.com/schemas/product-holon-v1 \
  --context-id https://gs1-product.perdl.com/contexts/product-holon-v1.jsonld \
  --output /tmp/gs1-product-profile-v1
```

Choose an output directory that does not already exist. Replacement is deliberately
refused: changing a profile used by issued credentials requires preserving the old
pinned version and deliberately choosing a new profile version where appropriate.
If `--products-dir` is omitted, the helper searches `docs/products` relative to the
current directory. `--profile-id` and `--context-id` default to the URLs above.

The generated profile for the current four products is also supplied in
`profiles/gs1-product-v1/`. It includes Sierra Nevada Torpedo IPA, Apple iPhone 17,
Tesco Raspberry Jam and Dal Giardino Risotto Rice. Their GTINs, source paths and
exact input file hashes appear in `profile.json`.

| Output | Purpose |
| --- | --- |
| `context.jsonld` | Holon context extension with a scoped Schema.org product context. |
| `schema.json` | Full Holon subject schema with shared product fields and observed value types. |
| `disclosure.schema.json` | Same product shape and core identity requirements; Holon `createdAt` becomes optional for disclosure. |
| `profile.json` | Profile/context identifiers, input inventory and hashes, mapped terms and upstream provenance. |
| `NOTICE.txt` | Attribution and license for the Schema.org mappings and description of changes. |

This step prepares the profile only. It does not generate issuer keys, sign
credentials, create runtime pins, publish the files or edit the target website.

## Mapping and preservation rules

Inputs currently require a single Schema.org context URL (`http` or `https`,
with or without its trailing slash). The helper accepts `@id`/`@type` and the
Schema.org aliases `id`/`type`. It discovers properties and classes recursively,
including `PropertyValue`, `additionalProperty`, `QuantitativeValue`, dimensions,
`model`, `mpn`, and `color`. The supplied files use Schema.org's spelling `color`;
the helper does not invent a `colour` alias.

Every term is looked up in the bundled official context. Definitions, datatype
coercions and referenced prefixes are copied without reinterpretation. In
particular the official JSON-LD context uses `http://schema.org/` term IRIs;
changing those to HTTPS would change the signed RDF graph. See
[Schema.org's developer documentation](https://schema.org/docs/developers.html).

The generated context extends `urn:holon:context:1.0`. It defines `ProductHolon`
as the profile ID plus `#ProductHolon`, and `product` as the profile ID plus
`#product`. Its scoped context keeps product meanings separate from Holon terms,
including `value`. When preparing an issuance input, place the original product
properties in `credentialSubject.claims.product` and omit only the product's
original root `@context`: the generated scoped context replaces it.

Unknown terms, custom/nested contexts and unsupported JSON-LD keywords fail
explicitly. They require a reviewed profile extension; they are not silently
removed or mapped to guessed IRIs. The helper rejects null values, duplicate JSON
properties, duplicate product IDs/GTINs, missing identity, malformed GTIN strings,
and an empty product directory. It supports these Schema.org sidecars; it is not
a universal JSON-LD schema inference engine.

## Schema rules

The full schema requires Holon `id`, `type`, `schemaVersion`, `createdAt`, and
`claims.product`. Holon type is `ProductHolon` and schema version is `1.0`.

Within each product, it requires:

- An absolute product identifier using the observed `@id` or `id` alias.
- A type using the observed `@type` or `type` alias, containing `Product`.
- A nonempty `name`.
- A 14-digit string `gtin14`, preserving leading zeros.

All other product properties are optional, including properties present in every
current sample. A property is still restricted to its observed shape when present.
Nested objects combine observed fields without making every field mandatory.
Arrays combine their observed item shapes; an empty-only array allows no items
until its item type can be deliberately defined. Unknown object fields are rejected.
If a property is observed with multiple types, the schema retains alternatives
rather than coercing the data.

For these files, string prices remain strings, numeric dimensions remain numbers,
and image arrays remain arrays. Missing reviews, ratings and ingredient claims
are not inserted. Existing demonstration or fictional-data statements remain
unchanged. Structural validation does not verify GTIN check digits, brand ownership,
food-safety assertions, commercial dates, or factual accuracy. Review the generated
schema before applying it beyond the observed examples.

## Use the helper from Python

The reusable function returns JSON-compatible artifacts without writing output:

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path("scripts").resolve()))
from product_profile import build_product_profile

artifacts = build_product_profile(
    Path("/var/software/gitrepos/chris-day/gs1-product/docs/products")
)
context = artifacts["context.jsonld"]
full_schema = artifacts["schema.json"]
```

The CLI writes those artifacts only after discovery and validation succeeds.
It exits nonzero on invalid inputs or an existing output directory.

## Validate and maintain

```bash
python3 scripts/test_product_profile.py
cargo test --locked --test product_profile
```

The Rust integration test checks RDF equivalence between the official context
and the generated scoped context, validates required and optional properties,
and issues and verifies genuine credentials with temporary test keys. It checks
that source file hashes and product values remain unchanged.

To run that test against the actual website products instead of synthetic test
fixtures:

```bash
GS1_PRODUCT_DIR=/var/software/gitrepos/chris-day/gs1-product/docs/products \
  cargo test --locked --test product_profile
```

This optional test does not use your persistent issuer key or modify your site.
The Python tests cover unmapped terms, nested contexts, nulls, duplicate keys,
duplicate identities, deterministic output and preservation of observed types.

The official snapshot is `contexts/vendor/schemaorg-2026-10-07.jsonld` with its
adjacent `.provenance.json`. Updates to it must be deliberate: verify the upstream
source, record its digest/provenance, regenerate profiles and rerun semantic tests.

## Next: configure issuance

Use the generated context ID and profile ID when creating the pinned
[configuration](CONFIGURATION.md). Pin both schema variants under this profile
ID. The schema's `credentialSchema` type remains `HolonSubjectSchema`.

Publishing context/schema files does not automatically make them trusted or
retrievable by this CLI. Both issuer and verifier configurations need the actual
local files and hashes. Follow the [issuer setup guide](GS1_PRODUCT_ISSUER.md)
for key and status management. The earlier [Risotto walkthrough](Product-VC-example.md)
uses a different, stricter sample profile; do not reuse its schema or reveal
pointers unchanged for these four sidecars.
