# Static HTTPS deployment

Generate into a directory ending in `.well-known`; its parent is the site root.
Origin-level DID documents go in `.well-known/did.json`. A DID such as
`did:web:issuer.example:departments:quality` goes in
`departments/quality/did.json`, outside `.well-known`, under the same root.
The supplied origin must match the DID's HTTPS origin. Percent-encoded ports are
supported; percent-encoded path components are conservatively rejected.

Upload only the staged `site/` tree. Never upload `keys/private`, `status` registries,
`config`, `trust`, replay databases, or the whole application data directory.
Generated directories are 0700 by default: deploy a copied public tree readable
by the static server rather than loosening private application directories.
No command here publishes data to a remote server.

| Resource | Content-Type | Recommended cache |
|---|---|---|
| DID document | application/did+ld+json | public, max-age=300, must-revalidate |
| Discovery, JWKS, manifest, OpenID metadata | application/json | public, max-age=300, must-revalidate |
| Signed status credentials | application/vc | public, max-age=300, must-revalidate |
| Public VC/VP files, if intentionally published | application/vc / application/vp | private/no-store as appropriate |

Enable TLS, disable directory indexes, redirects and HTTP content compression for
resolver resources, and preserve file bytes. Do not rewrite JSON after generating
manifest SHA-256 digests. The resolver rejects compressed HTTP responses to bound
resource use; internal status-list gzip is independently bounded.

Artefact files use atomic write/fsync/rename and the manifest is committed last.
This detects mixed generations during verification but is not a multi-file
snapshot transaction. For continuous availability, upload a whole new versioned
public directory and switch the web server's release pointer atomically. A partial
update must fail verification; never suppress digest errors to hide a deployment race.

Validate the local staged set before upload, then validate over HTTPS with an
explicit expected fingerprint from an independent channel. `--output-dir` checks
local files and their manifests; omitting it uses bounded HTTPS or pinned copies.
Use a fresh data/config directory when testing the actual remote server so local
generated pins do not mask deployment failures. Download success alone never
creates trust.

Refresh signed status lists with `status create --force` using the same ID, URL,
issuer and registry. Existing revocations/allocations are retained. Republish at
least every five minutes when using default offline pins and cache settings.
Metadata expires after one day and generated pins after five minutes; regenerate
metadata and refresh pins when required. Do not extend an expiry to bypass stale
content. Revocation has bounded cache latency, not instantaneous global visibility.

On rotation, retain backups, create a successor suite, explicitly update trust,
regenerate linkage/DID/JWKS/metadata/manifest together, and validate using the new
fingerprint. Retired keys are omitted from active metadata. Historical resolution
requires separately pinned historical records; the CLI cannot recover removed
DID keys from the current HTTPS document.

OpenID metadata is optional. Enable it only for an actual separately operated
OpenID4VCI service with explicit endpoints and matching capabilities. This CLI
does not provide those endpoints. Domain linkage uses the Holon VC2 application
profile and should not be submitted as a DIF VC1 domain linkage credential.
