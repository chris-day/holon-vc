#!/usr/bin/env bash
# Run from the repository root. Sections are included verbatim in the documentation.
# --8<-- [start:setup]
set -euo pipefail
umask 077
cargo build --locked --release

PRODUCT_REPO="$PWD"
PRODUCT_RUN="$(mktemp -d /tmp/holon-product-manual.XXXXXX)"
export PRODUCT_REPO PRODUCT_RUN
PRODUCT_DID='did:web:product-issuer.example'
PRODUCT_SCHEMA='urn:example:product-holon:1.0'
printf 'Artifacts: %s\n' "$PRODUCT_RUN"
read -r -s -p 'Choose a password for the demonstration keys: ' PRODUCT_PASSWORD
printf '\n'
test -n "$PRODUCT_PASSWORD"

vc() {
  "$PRODUCT_REPO/target/release/holon-vc" \
    --data-dir "$PRODUCT_RUN/data" \
    --config "$PRODUCT_RUN/config.toml" \
    --offline --output-format json "$@"
}
sign_vc() {
  printf '%s\n' "$PRODUCT_PASSWORD" | vc "$@" --password-stdin
}
# --8<-- [end:setup]

# --8<-- [start:prepare]
python3 - <<'PY'
import datetime as dt
import hashlib
import json
import os
from pathlib import Path

repo = Path(os.environ['PRODUCT_REPO'])
work = Path(os.environ['PRODUCT_RUN'])
example = repo / 'examples/product'
now = dt.datetime.now(dt.timezone.utc)
expires = (now + dt.timedelta(days=1)).isoformat()
(work / 'expires.txt').write_text(expires)
source = json.loads((example / 'product.jsonld').read_text())
product = {k: v for k, v in source.items() if k != '@context'}
holon = {
    'id': 'urn:example:holon:product:09506000134352',
    'type': 'ProductHolon', 'schemaVersion': '1.0',
    'createdAt': now.isoformat(), 'claims': {'product': product},
    'source': {'id': 'did:web:product-issuer.example', 'kind': 'demonstration-publisher'},
    'evidence': [], 'relatedHolons': [],
}
(work / 'product.holon.json').write_text(json.dumps(holon, indent=2) + '\n')

def sha(name):
    return hashlib.sha256((example / name).read_bytes()).hexdigest()

(work / 'config.toml').write_text(f'''
[contexts."urn:example:product-context:1.0"]
path = {json.dumps(str(example / 'context.jsonld'))}
sha256 = "{sha('context.jsonld')}"
expires = "{expires}"
media_type = "application/ld+json"

[schemas."urn:example:product-holon:1.0"]
full = {json.dumps(str(example / 'schema.json'))}
disclosure = {json.dumps(str(example / 'disclosure.schema.json'))}
context = "urn:example:product-context:1.0"
sha256 = "{sha('schema.json')}"
disclosure_sha256 = "{sha('disclosure.schema.json')}"
''')
PY
PRODUCT_EXPIRES="$(cat "$PRODUCT_RUN/expires.txt")"
# --8<-- [end:prepare]

# --8<-- [start:keys]
sign_vc key setup --id issuer --controller "$PRODUCT_DID" --algorithm ed25519 \
  > "$PRODUCT_RUN/issuer-key.json"
sign_vc key setup --id selective --controller "$PRODUCT_DID" --algorithm p256 \
  > "$PRODUCT_RUN/selective-key.json"

vc suite setup --name issuer \
  --key "$PRODUCT_RUN/data/keys/private/issuer.json" \
  --verification-method "$PRODUCT_DID#issuer" --cryptosuite eddsa-rdfc-2022
vc suite setup --name selective \
  --key "$PRODUCT_RUN/data/keys/private/selective.json" \
  --verification-method "$PRODUCT_DID#selective" --cryptosuite ecdsa-sd-2023

for PRODUCT_KEY in issuer selective; do
  PRODUCT_FINGERPRINT="$(python3 -c \
    'import json,sys; print(json.load(open(sys.argv[1]))["fingerprint"])' \
    "$PRODUCT_RUN/$PRODUCT_KEY-key.json")"
  vc trust add --id "$PRODUCT_KEY" --issuer "$PRODUCT_DID" \
    --verification-method "$PRODUCT_DID#$PRODUCT_KEY" \
    --fingerprint "$PRODUCT_FINGERPRINT" \
    --credential-type HolonCredential --schema "$PRODUCT_SCHEMA" \
    --purpose holon-assertion
 done
# --8<-- [end:keys]

# --8<-- [start:publish]
sign_vc well-known generate --origin https://product-issuer.example \
  --issuer-did "$PRODUCT_DID" --suite issuer
sign_vc status create --id products \
  --url https://product-issuer.example/status/products --suite issuer
# --8<-- [end:publish]

# --8<-- [start:issue]
for PRODUCT_SUITE in issuer selective; do
  sign_vc credential issue --holon "$PRODUCT_RUN/product.holon.json" \
    --schema-id "$PRODUCT_SCHEMA" --suite "$PRODUCT_SUITE" \
    --status-list "$PRODUCT_RUN/data/status/products.json" \
    --expires "$PRODUCT_EXPIRES" --output "$PRODUCT_RUN/$PRODUCT_SUITE.vc.json"
  vc credential verify --credential "$PRODUCT_RUN/$PRODUCT_SUITE.vc.json" \
    --threshold trusted-assertion --output "$PRODUCT_RUN/$PRODUCT_SUITE.report.json"
done
# --8<-- [end:issue]

# --8<-- [start:derive]
vc credential derive --credential "$PRODUCT_RUN/selective.vc.json" \
  --reveal "$PRODUCT_REPO/examples/product/reveal.json" \
  --output "$PRODUCT_RUN/derived.vc.json"
vc credential verify --credential "$PRODUCT_RUN/derived.vc.json" \
  --threshold trusted-assertion --output "$PRODUCT_RUN/derived.report.json"

python3 - <<'PY'
import json, os
from pathlib import Path
work = Path(os.environ['PRODUCT_RUN'])
for name in ['issuer', 'selective', 'derived']:
    report = json.loads((work / f'{name}.report.json').read_text())
    assert report['decision'] == 'trusted-assertion'
    assert report['cryptographicallyValid'] and report['status'] == 'active'
product = json.loads((work / 'derived.vc.json').read_text())['credentialSubject']['claims']['product']
assert product['gtin14'] == '09506000134352'
assert 'gs1:ingredientStatement' in product and 'gs1:allergenStatement' in product
assert not {'offers', 'review', 'aggregateRating', 'sku'} & product.keys()
print('PASS: all three credentials verify; selected claims retained and other claims omitted')
PY
# --8<-- [end:derive]

# --8<-- [start:tamper]
python3 - <<'PY'
import json, os
from pathlib import Path
work = Path(os.environ['PRODUCT_RUN'])
vc = json.loads((work / 'issuer.vc.json').read_text())
vc['credentialSubject']['claims']['product']['offers']['price'] = 0.01
(work / 'tampered-price.json').write_text(json.dumps(vc))
PY

if vc credential verify --credential "$PRODUCT_RUN/tampered-price.json" \
    > "$PRODUCT_RUN/tampered-price.report.json"; then
  printf '%s\n' 'ERROR: tampered credential unexpectedly accepted' >&2
  exit 1
else
  PRODUCT_EXIT=$?
  test "$PRODUCT_EXIT" -eq 5
fi
python3 - <<'PY'
import json, os
from pathlib import Path
report = json.loads((Path(os.environ['PRODUCT_RUN']) / 'tampered-price.report.json').read_text())
assert not report['cryptographicallyValid']
print('PASS: changed price rejected cryptographically (exit 5)')
PY
# --8<-- [end:tamper]

# --8<-- [start:html]
python3 - <<'PY'
import html, json, os
from pathlib import Path
work = Path(os.environ['PRODUCT_RUN'])
vc = json.loads((work / 'issuer.vc.json').read_text())
product = vc['credentialSubject']['claims']['product']
embedded = json.dumps(vc, indent=2, ensure_ascii=True).replace('<', '\\u003c')
assert json.loads(embedded) == vc
page = f'''<!doctype html>
<html lang="en"><meta charset="utf-8">
<title>Product VC example</title>
<h1>{html.escape(product['name'])}</h1>
<p>Local demonstration issuer; no brand-owner endorsement. No live verification.</p>
<p><a href="issuer.vc.json">Full credential</a> | <a href="derived.vc.json">Disclosed credential</a></p>
<script id="product-credential" type="application/ld+json">{embedded}</script>
<pre>{html.escape(json.dumps(product, indent=2))}</pre>
</html>'''
(work / 'product.html').write_text(page)
print('PASS: HTML embeds the complete issued credential')
print(f'Open {work / "product.html"} in your browser')
PY
unset PRODUCT_PASSWORD
# --8<-- [end:html]
