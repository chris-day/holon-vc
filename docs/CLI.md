# Complete CLI reference
Generated from the implemented Clap command tree. See README.md and the executable
walkthrough in scripts/workflow.py for values used in a complete working deployment.

## key setup

```text
Generate an encrypted signing key

Usage: holon-vc key setup [OPTIONS] --id <VALUE> --controller <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --id <VALUE>             Explicit identifier, value, or local file path (see command reference)
      --controller <VALUE>     Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --algorithm <VALUE>      Key algorithm: ed25519 (default) or p256
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --offline                Disable all network resolution
      --private-key <VALUE>    Explicit identifier, value, or local file path (see command reference)
      --public-key <VALUE>     Explicit identifier, value, or local file path (see command reference)
      --quiet                  Suppress nonessential diagnostics
      --force                  Replace existing output; never bypass filesystem safety checks
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
      --password-stdin         Read password from stdin; never provide secrets in arguments
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## key inspect

```text
Inspect public key metadata

Usage: holon-vc key inspect [OPTIONS] --key <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --key <VALUE>            Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --offline                Disable all network resolution
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## key export-public

```text
Export a public verification method

Usage: holon-vc key export-public [OPTIONS] --key <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --key <VALUE>            Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --output <VALUE>         Destination JSON file; JSON report also available on stdout
      --force                  Replace existing output; never bypass filesystem safety checks
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --offline                Disable all network resolution
      --password-stdin         Read password from stdin; never provide secrets in arguments
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## key rotate

```text
Create a successor key and record rotation

Usage: holon-vc key rotate [OPTIONS] --key <VALUE> --id <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --key <VALUE>            Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --id <VALUE>             Explicit identifier, value, or local file path (see command reference)
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --password-stdin         Read password from stdin; never provide secrets in arguments
      --offline                Disable all network resolution
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## key list

```text
List local public keys

Usage: holon-vc key list [OPTIONS]

Options:
      --config <VALUE>         TOML configuration file
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --offline                Disable all network resolution
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## suite setup

```text
Bind a key to a suite

Usage: holon-vc suite setup [OPTIONS] --name <VALUE> --key <VALUE> --verification-method <VALUE>

Options:
      --config <VALUE>               TOML configuration file
      --name <VALUE>                 Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>             Private application data directory [default: holon-vc-data]
      --key <VALUE>                  Explicit identifier, value, or local file path (see command reference)
      --output-format <VALUE>        Output format [default: human] [possible values: human, json]
      --verification-method <VALUE>  Explicit identifier, value, or local file path (see command reference)
      --cryptosuite <VALUE>          eddsa-rdfc-2022 (default), ecdsa-sd-2023, or Ed25519Signature2020
      --offline                      Disable all network resolution
      --purpose <VALUE>              Explicit identifier, value, or local file path (see command reference)
      --quiet                        Suppress nonessential diagnostics
      --legacy                       Explicitly authorize legacy issuance; unsuitable for new deployments
      --verbose                      Enable redacted diagnostic logging
      --force                        Replace existing output; never bypass filesystem safety checks
      --no-color                     Disable terminal colors
  -h, --help                         Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## suite inspect

```text
Inspect a suite

Usage: holon-vc suite inspect [OPTIONS] --name <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --name <VALUE>           Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --offline                Disable all network resolution
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## suite list

```text
List suites

Usage: holon-vc suite list [OPTIONS]

Options:
      --config <VALUE>         TOML configuration file
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --offline                Disable all network resolution
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## trust add

```text
Add a scoped issuer policy

Usage: holon-vc trust add [OPTIONS]

Options:
      --config <VALUE>               TOML configuration file
      --policy <VALUE>               Trust-policy JSON file
      --data-dir <VALUE>             Private application data directory [default: holon-vc-data]
      --issuer <VALUE>               Explicit identifier, value, or local file path (see command reference)
      --output-format <VALUE>        Output format [default: human] [possible values: human, json]
      --verification-method <VALUE>  Explicit identifier, value, or local file path (see command reference)
      --fingerprint <VALUE>          Explicit identifier, value, or local file path (see command reference)
      --offline                      Disable all network resolution
      --credential-type <VALUE>      Explicit identifier, value, or local file path (see command reference)
      --quiet                        Suppress nonessential diagnostics
      --schema <VALUE>               Explicit identifier, value, or local file path (see command reference)
      --verbose                      Enable redacted diagnostic logging
      --no-color                     Disable terminal colors
      --purpose <VALUE>              Explicit identifier, value, or local file path (see command reference)
      --id <VALUE>                   Explicit identifier, value, or local file path (see command reference)
      --force                        Replace existing output; never bypass filesystem safety checks
  -h, --help                         Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## trust remove

```text
Remove a trust policy

Usage: holon-vc trust remove [OPTIONS] --id <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --id <VALUE>             Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --offline                Disable all network resolution
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## trust enable

```text
Enable a policy

Usage: holon-vc trust enable [OPTIONS] --id <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --id <VALUE>             Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --offline                Disable all network resolution
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## trust disable

```text
Disable a policy

Usage: holon-vc trust disable [OPTIONS] --id <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --id <VALUE>             Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --offline                Disable all network resolution
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## trust inspect

```text
Inspect a policy

Usage: holon-vc trust inspect [OPTIONS] --id <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --id <VALUE>             Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --offline                Disable all network resolution
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## trust list

```text
List policies

Usage: holon-vc trust list [OPTIONS]

Options:
      --config <VALUE>         TOML configuration file
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --offline                Disable all network resolution
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## credential issue

```text
Validate and issue a Holon credential

Usage: holon-vc credential issue [OPTIONS] --holon <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --holon <VALUE>          Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --schema <VALUE>         Explicit identifier, value, or local file path (see command reference)
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --schema-id <VALUE>      Explicit identifier, value, or local file path (see command reference)
      --offline                Disable all network resolution
      --suite <VALUE>          Suite name or file; defaults to configured default_suite
      --quiet                  Suppress nonessential diagnostics
      --status-list <VALUE>    Local status registry; defaults to configured default_status_list
      --output <VALUE>         Destination JSON file; JSON report also available on stdout
      --verbose                Enable redacted diagnostic logging
      --expires <VALUE>        Explicit identifier, value, or local file path (see command reference)
      --no-color               Disable terminal colors
      --legacy                 Explicitly authorize legacy issuance; unsuitable for new deployments
      --force                  Replace existing output; never bypass filesystem safety checks
      --password-stdin         Read password from stdin; never provide secrets in arguments
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## credential derive

```text
Derive genuine selective disclosure without issuer keys

Usage: holon-vc credential derive [OPTIONS] --credential <VALUE> --reveal <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --credential <VALUE>     Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --reveal <VALUE>         Versioned reveal document containing selectivePointers
      --output <VALUE>         Destination JSON file; JSON report also available on stdout
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --offline                Disable all network resolution
      --trust-store <VALUE>    Explicit identifier, value, or local file path (see command reference)
      --force                  Replace existing output; never bypass filesystem safety checks
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## credential reissue-redacted

```text
Issuer-controlled redacted reissuance with a new ID

Usage: holon-vc credential reissue-redacted [OPTIONS] --credential <VALUE> --reveal <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --credential <VALUE>     Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --reveal <VALUE>         Versioned reveal document containing selectivePointers
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --suite <VALUE>          Suite name or file; defaults to configured default_suite
      --offline                Disable all network resolution
      --status-list <VALUE>    Local status registry; defaults to configured default_status_list
      --output <VALUE>         Destination JSON file; JSON report also available on stdout
      --quiet                  Suppress nonessential diagnostics
      --force                  Replace existing output; never bypass filesystem safety checks
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
      --password-stdin         Read password from stdin; never provide secrets in arguments
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## credential verify

```text
Verify cryptography, status, schema, evidence and trust

Usage: holon-vc credential verify [OPTIONS] --credential <VALUE>

Options:
      --config <VALUE>                  TOML configuration file
      --credential <VALUE>              Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>                Private application data directory [default: holon-vc-data]
      --trust-store <VALUE>             Explicit identifier, value, or local file path (see command reference)
      --output <VALUE>                  Destination JSON file; JSON report also available on stdout
      --output-format <VALUE>           Output format [default: human] [possible values: human, json]
      --offline                         Disable all network resolution
      --threshold <VALUE>               Acceptance threshold: authentic-assertion (default), trusted-assertion, corroborated [possible values: authentic-assertion, trusted-assertion, corroborated]
      --conflicting-credential <VALUE>  Explicit identifier, value, or local file path (see command reference)
      --quiet                           Suppress nonessential diagnostics
      --force                           Replace existing output; never bypass filesystem safety checks
      --verbose                         Enable redacted diagnostic logging
      --local-development               Permit only origins explicitly listed in development_origins
      --no-color                        Disable terminal colors
  -h, --help                            Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## credential inspect

```text
Inspect untrusted credential data without authenticating it

Usage: holon-vc credential inspect [OPTIONS] --credential <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --credential <VALUE>     Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --offline                Disable all network resolution
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## presentation create

```text
Package credentials and optionally authenticate a holder

Usage: holon-vc presentation create [OPTIONS] --credential <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --credential <VALUE>     Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --holder <VALUE>         Explicit identifier, value, or local file path (see command reference)
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --suite <VALUE>          Suite name or file; defaults to configured default_suite
      --challenge <VALUE>      Verifier-issued, single-use nonce (required for signed presentations)
      --offline                Disable all network resolution
      --domain <VALUE>         Verifier domain/audience; checked exactly
      --quiet                  Suppress nonessential diagnostics
      --expires <VALUE>        Explicit identifier, value, or local file path (see command reference)
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
      --output <VALUE>         Destination JSON file; JSON report also available on stdout
      --sign                   Authenticate holder with a signed presentation
      --force                  Replace existing output; never bypass filesystem safety checks
      --password-stdin         Read password from stdin; never provide secrets in arguments
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## presentation verify

```text
Verify embedded credentials and holder authentication

Usage: holon-vc presentation verify [OPTIONS] --presentation <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --presentation <VALUE>   Explicit identifier, value, or local file path (see command reference)
      --challenge <VALUE>      Verifier-issued, single-use nonce (required for signed presentations)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --domain <VALUE>         Verifier domain/audience; checked exactly
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --offline                Disable all network resolution
      --trust-store <VALUE>    Explicit identifier, value, or local file path (see command reference)
      --output <VALUE>         Destination JSON file; JSON report also available on stdout
      --quiet                  Suppress nonessential diagnostics
      --threshold <VALUE>      Acceptance threshold: authentic-assertion (default), trusted-assertion, corroborated [possible values: authentic-assertion, trusted-assertion, corroborated]
      --verbose                Enable redacted diagnostic logging
      --force                  Replace existing output; never bypass filesystem safety checks
      --no-color               Disable terminal colors
      --local-development      Permit only origins explicitly listed in development_origins
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## presentation inspect

```text
Inspect an untrusted presentation

Usage: holon-vc presentation inspect [OPTIONS] --presentation <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --presentation <VALUE>   Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --offline                Disable all network resolution
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## status create

```text
Create signed status lists

Usage: holon-vc status create [OPTIONS] --id <VALUE> --url <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --id <VALUE>             Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --url <VALUE>            Explicit identifier, value, or local file path (see command reference)
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --suite <VALUE>          Suite name or file; defaults to configured default_suite
      --offline                Disable all network resolution
      --output <VALUE>         Destination JSON file; JSON report also available on stdout
      --force                  Replace existing output; never bypass filesystem safety checks
      --quiet                  Suppress nonessential diagnostics
      --password-stdin         Read password from stdin; never provide secrets in arguments
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## status revoke

```text
Permanently revoke a credential

Usage: holon-vc status revoke [OPTIONS] --status-list <VALUE> --credential <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --status-list <VALUE>    Local status registry; defaults to configured default_status_list
      --credential <VALUE>     Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --suite <VALUE>          Suite name or file; defaults to configured default_suite
      --offline                Disable all network resolution
      --password-stdin         Read password from stdin; never provide secrets in arguments
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## status suspend

```text
Suspend a credential

Usage: holon-vc status suspend [OPTIONS] --status-list <VALUE> --credential <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --status-list <VALUE>    Local status registry; defaults to configured default_status_list
      --credential <VALUE>     Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --suite <VALUE>          Suite name or file; defaults to configured default_suite
      --offline                Disable all network resolution
      --password-stdin         Read password from stdin; never provide secrets in arguments
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## status restore

```text
Clear suspension; never undo revocation

Usage: holon-vc status restore [OPTIONS] --status-list <VALUE> --credential <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --status-list <VALUE>    Local status registry; defaults to configured default_status_list
      --credential <VALUE>     Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --suite <VALUE>          Suite name or file; defaults to configured default_suite
      --offline                Disable all network resolution
      --password-stdin         Read password from stdin; never provide secrets in arguments
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## status inspect

```text
Inspect a local status registry

Usage: holon-vc status inspect [OPTIONS] --status-list <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --status-list <VALUE>    Local status registry; defaults to configured default_status_list
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --offline                Disable all network resolution
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## well-known generate

```text
Stage public metadata and signed domain linkage

Usage: holon-vc well-known generate [OPTIONS] --origin <VALUE> --issuer-did <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --origin <VALUE>         Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --issuer-did <VALUE>     Explicit identifier, value, or local file path (see command reference)
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --public-key <VALUE>     Explicit identifier, value, or local file path (see command reference)
      --offline                Disable all network resolution
      --trust-policy <VALUE>   Explicit identifier, value, or local file path (see command reference)
      --quiet                  Suppress nonessential diagnostics
      --suite <VALUE>          Suite name or file; defaults to configured default_suite
      --output-dir <VALUE>     Explicit identifier, value, or local file path (see command reference)
      --verbose                Enable redacted diagnostic logging
      --display-name <VALUE>   Explicit identifier, value, or local file path (see command reference)
      --no-color               Disable terminal colors
      --jwks                   Explicit identifier, value, or local file path (see command reference)
      --openid                 Explicit identifier, value, or local file path (see command reference)
      --force                  Replace existing output; never bypass filesystem safety checks
      --password-stdin         Read password from stdin; never provide secrets in arguments
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## well-known validate

```text
Validate signatures, pins and metadata consistency

Usage: holon-vc well-known validate [OPTIONS] --origin <VALUE> --issuer-did <VALUE> --expected-fingerprint <VALUE>

Options:
      --config <VALUE>                TOML configuration file
      --origin <VALUE>                Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>              Private application data directory [default: holon-vc-data]
      --issuer-did <VALUE>            Explicit identifier, value, or local file path (see command reference)
      --expected-fingerprint <VALUE>  Explicit identifier, value, or local file path (see command reference)
      --output-format <VALUE>         Output format [default: human] [possible values: human, json]
      --offline                       Disable all network resolution
      --output <VALUE>                Destination JSON file; JSON report also available on stdout
      --output-dir <VALUE>            Explicit identifier, value, or local file path (see command reference)
      --quiet                         Suppress nonessential diagnostics
      --force                         Replace existing output; never bypass filesystem safety checks
      --verbose                       Enable redacted diagnostic logging
      --local-development             Permit only origins explicitly listed in development_origins
      --no-color                      Disable terminal colors
  -h, --help                          Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```

## well-known inspect

```text
Inspect a local publication manifest

Usage: holon-vc well-known inspect [OPTIONS] --output-dir <VALUE>

Options:
      --config <VALUE>         TOML configuration file
      --output-dir <VALUE>     Explicit identifier, value, or local file path (see command reference)
      --data-dir <VALUE>       Private application data directory [default: holon-vc-data]
      --output-format <VALUE>  Output format [default: human] [possible values: human, json]
      --offline                Disable all network resolution
      --quiet                  Suppress nonessential diagnostics
      --verbose                Enable redacted diagnostic logging
      --no-color               Disable terminal colors
  -h, --help                   Print help

Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.
```
