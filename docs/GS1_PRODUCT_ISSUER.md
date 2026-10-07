# Enable gs1-product.perdl.com as an issuer

The issuer DID is **`did:web:gs1-product.perdl.com`**. Its verification document
is published at **https://gs1-product.perdl.com/.well-known/did.json**.
`holon-vc` signs on your private machine; Zensical publishes only public files.
The website does not need the signing key or an issuance server.

New issuer metadata, domain-linkage credentials and signed status lists are valid
for **365 days**. Local resource pins and status cache freshness remain five
minutes. This is a fixed 365-day period, not a calendar-year calculation. Existing
artifacts are not extended automatically: regenerate and redeploy them.
Individual product credentials have their own expiry; pass `--expires` deliberately.

## 1. Build and create persistent private storage

Use Linux, Bash, Rust/Cargo and Python 3.11 or later. Run from the `holon-vc`
repository root and keep the same shell session throughout. The target site's
Zensical environment must already be installed. Initial dependency downloads need
network access. Replace the website checkout path below with its actual location.

```bash
set -euo pipefail
umask 077
cargo build --locked --release

HOLON_REPO="$PWD"
HOLON_BIN="$HOLON_REPO/target/release/holon-vc"
ISSUER_DATA="$HOME/.local/share/holon-vc/gs1-product"
ISSUER_DID='did:web:gs1-product.perdl.com'
ISSUER_ORIGIN='https://gs1-product.perdl.com'
ISSUER_SITE_REPO='/absolute/path/to/gs1-product-site'
mkdir -p "$ISSUER_DATA"

vc() {
  "$HOLON_BIN" --data-dir "$ISSUER_DATA" --offline --output-format json "$@"
}
```

Keep this private directory outside the website checkout and back it up securely.
Commands that sign or create keys prompt for a password. Retain the password for
later issuance, renewal and status changes. Do not use the ephemeral automated
example's keys for this persistent issuer.

## 2. Generate keys and bind suites

Run key setup once. Reuse these keys for refresh; do not overwrite them each time.

```bash
vc key setup --id issuer --controller "$ISSUER_DID" --algorithm ed25519
vc suite setup --name issuer \
  --key "$ISSUER_DATA/keys/private/issuer.json" \
  --verification-method "$ISSUER_DID#issuer" --cryptosuite eddsa-rdfc-2022
```

For selective disclosure, also generate a P-256 key before publishing the DID:

```bash
vc key setup --id selective --controller "$ISSUER_DID" --algorithm p256
vc suite setup --name selective \
  --key "$ISSUER_DATA/keys/private/selective.json" \
  --verification-method "$ISSUER_DID#selective" --cryptosuite ecdsa-sd-2023
```

## 3. Generate and validate public identity and status files

```bash
vc well-known generate \
  --origin "$ISSUER_ORIGIN" --issuer-did "$ISSUER_DID" \
  --suite issuer --display-name 'GS1 Product — PERDL' --jwks

vc status create --id products \
  --url "$ISSUER_ORIGIN/status/products" --suite issuer

ISSUER_FINGERPRINT="$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["fingerprint"])' \
  "$ISSUER_DATA/keys/public/issuer.json")"
printf 'Issuer fingerprint: %s\n' "$ISSUER_FINGERPRINT"

vc well-known validate \
  --origin "$ISSUER_ORIGIN" --issuer-did "$ISSUER_DID" \
  --expected-fingerprint "$ISSUER_FINGERPRINT" \
  --output-dir "$ISSUER_DATA/site/.well-known"
```

Validation must exit 0. Retain the fingerprint through an independently trusted
channel. The display name can be changed to your publisher's name; it conveys no
GS1 endorsement. Do not enable `--openid` without separately operated issuance
services. Domain linkage here uses the Holon VC2 application profile, not DIF VC1.

The public subtree is:

```text
site/
  .well-known/
    did.json
    did-configuration.json
    holon-issuer.json
    jwks.json
    manifest.json
  status/products/
    revocation.json
    suspension.json
```

## 4. Integrate with the target Zensical site

Copy only the public tree into the site's source checkout:

```bash
mkdir -p "$ISSUER_SITE_REPO/issuer-public"
cp -R "$ISSUER_DATA/site/." "$ISSUER_SITE_REPO/issuer-public/"
find "$ISSUER_SITE_REPO/issuer-public" -type d -exec chmod 755 {} +
find "$ISSUER_SITE_REPO/issuer-public" -type f -exec chmod 644 {} +
```

Set the following value inside the target site's existing `[project]` section;
do not replace its other settings:

```toml
site_url = "https://gs1-product.perdl.com/"
```

Build, then copy public issuer files into the generated output. Do this **after
every clean build**, before uploading the site. The Python command reads the
actual `site_dir` from the target configuration.

```bash
cd "$ISSUER_SITE_REPO"
.venv/bin/zensical build --clean --strict
SITE_OUTPUT="$(.venv/bin/python -c \
  'import tomllib; print(tomllib.load(open("zensical.toml","rb"))["project"].get("site_dir","site"))')"
cp -R issuer-public/. "$SITE_OUTPUT/"
test -s "$SITE_OUTPUT/.well-known/did.json"
test -s "$SITE_OUTPUT/status/products/revocation.json"
test -s "$SITE_OUTPUT/status/products/suspension.json"
```

Commit `issuer-public/` with the target site's public sources and add this
post-build copy to its deployment workflow. Deploy using that site's existing
hosting process. Never copy private keys, the private status registry, configuration,
trust policies or the whole issuer data directory. Preserve public JSON bytes so
manifest digests still match.

If using GitHub Pages with `actions/upload-pages-artifact@v5`, enable hidden files
so `.well-known` is included. Set `path` to that site's actual output directory:

```yaml
- uses: actions/upload-pages-artifact@v5
  with:
    path: site
    include-hidden-files: true
```

See [Zensical configuration](https://zensical.org/docs/setup/basics/) and the
[Pages artifact action](https://github.com/actions/upload-pages-artifact/blob/v5/action.yml).
This guide does not configure DNS, TLS or the hosting provider automatically.

## 5. Validate the deployed site over HTTPS

The following URLs must return HTTP 200 and JSON, with an accepted JSON content
type. They must not redirect, return an HTML fallback, or apply HTTP content
compression. Configure the host/CDN for these paths; the current resolver rejects
redirects and compressed HTTP responses. See [deployment requirements](DEPLOYMENT.md).

```bash
for resource in \
  .well-known/did.json \
  .well-known/did-configuration.json \
  .well-known/holon-issuer.json \
  .well-known/jwks.json \
  .well-known/manifest.json \
  status/products/revocation.json \
  status/products/suspension.json
do
  curl --fail --silent --show-error \
    --header 'Accept-Encoding: identity' \
    --dump-header - --output /dev/null "$ISSUER_ORIGIN/$resource"
done

REMOTE_CHECK="$(mktemp -d /tmp/gs1-product-check.XXXXXX)"
"$HOLON_BIN" --data-dir "$REMOTE_CHECK" --output-format json \
  well-known validate \
  --origin "$ISSUER_ORIGIN" --issuer-did "$ISSUER_DID" \
  --expected-fingerprint "$ISSUER_FINGERPRINT"
```

There is intentionally no `--offline` or local resource configuration in this
last command. A fresh directory prevents local pins from masking deployment
failures. Expected result: exit 0. This checks identity artifacts; the credential
verification below additionally checks the signed status lists.

## 6. Issue a one-year smoke-test credential

Return to the Rust repository. If more than five minutes have elapsed since
step 3, run the refresh commands in step 7 first to renew local pins.

```bash
cd "$HOLON_REPO"
CREDENTIAL_EXPIRES="$(python3 -c \
  'from datetime import datetime,timedelta,timezone; print((datetime.now(timezone.utc)+timedelta(days=365)).isoformat())')"
vc credential issue --holon "$HOLON_REPO/examples/holon.json" \
  --suite issuer --status-list "$ISSUER_DATA/status/products.json" \
  --expires "$CREDENTIAL_EXPIRES" --output "$ISSUER_DATA/example.vc.json"
vc credential verify --credential "$ISSUER_DATA/example.vc.json"

"$HOLON_BIN" --data-dir "$REMOTE_CHECK" --output-format json \
  credential verify --credential "$ISSUER_DATA/example.vc.json"
```

The smoke test uses the bundled Holon profile to isolate issuer setup from product
schema configuration. Verification should report an authentic assertion with
active status. Trust is a separate verifier decision; domain control alone does
not create a `trusted-assertion` policy.

For [GS1 Risotto Rice](Product-VC-example.md), retain the product context and paired
schemas from the guide, but use this persistent data directory, these suites,
`did:web:gs1-product.perdl.com` as the source, and this `products` status registry.
Pass the generated product `config.toml` using `--config` and
`--schema-id urn:example:product-holon:1.0` when issuing. Use `--suite selective`
for actual disclosure. The product's GS1 Digital Link ID remains unchanged.
The product demo deliberately retains its one-day credential/context expiry;
for a persistent product profile, choose its context-pin expiry and credential
`--expires` explicitly. Verifiers must receive matching context/schema pins and
establish trust independently.

## 7. Refresh and publish changes

Use the same persistent data directory and original key password:

```bash
vc well-known generate \
  --origin "$ISSUER_ORIGIN" --issuer-did "$ISSUER_DID" \
  --suite issuer --display-name 'GS1 Product — PERDL' --jwks --force
vc status create --id products \
  --url "$ISSUER_ORIGIN/status/products" --suite issuer --force
```

Repeat steps 4 and 5 to deploy and verify. Refreshing creates newly signed
365-day artifacts; it does not change an already issued product credential's
expiry. Status refresh preserves allocations, suspensions and revocations.
Refresh before annual expiration and publish status changes promptly. Maintain
short HTTP cache lifetimes, typically 300 seconds, regardless of signature lifetime.
Local generated pins still expire after five minutes and need refresh before
later offline operations. A 365-day signature lifetime is not permission to trust
an old cached status list for a year.

Back up private keys and the status registry. Use explicit key rotation rather
than rerunning setup over an existing key. Publication should switch a complete
public snapshot to avoid mismatched manifests during deployment.
