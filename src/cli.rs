use clap::{Arg, ArgAction, Command};

fn option(name: &'static str, help: &'static str) -> Arg {
    {
        let a = Arg::new(name).long(name).help(help).value_name("VALUE");
        if name == "threshold" {
            a.value_parser(["authentic-assertion", "trusted-assertion", "corroborated"])
        } else {
            a
        }
    }
}
fn flag(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .help(help)
        .action(ArgAction::SetTrue)
}
fn leaf(
    name: &'static str,
    about: &'static str,
    required: &[&'static str],
    optional: &[&'static str],
    flags: &[&'static str],
) -> Command {
    let mut c=Command::new(name).about(about).after_help("Secrets are never accepted as command-line values. Use a secure prompt or --password-stdin. Verification establishes attributed assertions, never objective truth.");
    for &name in required {
        c = c.arg(option(name, description(name)).required(true));
    }
    for &name in optional {
        c = c.arg(option(name, description(name)));
    }
    for &name in flags {
        c = c.arg(flag(name, description(name)));
    }
    c
}
fn description(name: &str) -> &'static str {
    match name {
        "algorithm" => "Key algorithm: ed25519 (default) or p256",
        "cryptosuite" => "eddsa-rdfc-2022 (default), ecdsa-sd-2023, or Ed25519Signature2020",
        "legacy" => "Explicitly authorize legacy issuance; unsuitable for new deployments",
        "force" => "Replace existing output; never bypass filesystem safety checks",
        "password-stdin" => "Read password from stdin; never provide secrets in arguments",
        "challenge" => "Verifier-issued, single-use nonce (required for signed presentations)",
        "domain" => "Verifier domain/audience; checked exactly",
        "reveal" => "Versioned reveal document containing selectivePointers",
        "threshold" => {
            "Acceptance threshold: authentic-assertion (default), trusted-assertion, corroborated"
        }
        "local-development" => "Permit only origins explicitly listed in development_origins",
        "suite" => "Suite name or file; defaults to configured default_suite",
        "status-list" => "Local status registry; defaults to configured default_status_list",
        "output" => "Destination JSON file; JSON report also available on stdout",
        "policy" => "Trust-policy JSON file",
        "sign" => "Authenticate holder with a signed presentation",
        _ => "Explicit identifier, value, or local file path (see command reference)",
    }
}
pub fn command() -> Command {
    Command::new("holon-vc").version(env!("CARGO_PKG_VERSION")).about("Issue and verify attributed Holon assertions")
    .subcommand_required(true).arg_required_else_help(true)
    .arg(option("config","TOML configuration file").global(true))
    .arg(option("data-dir","Private application data directory").default_value("holon-vc-data").global(true))
    .arg(option("output-format","Output format").value_parser(["human","json"]).default_value("human").global(true))
    .args([flag("offline","Disable all network resolution").global(true),flag("quiet","Suppress nonessential diagnostics").global(true),flag("verbose","Enable redacted diagnostic logging").global(true),flag("no-color","Disable terminal colors").global(true)])
    .subcommand(Command::new("key").about("Manage encrypted local identity keys").subcommand_required(true).after_help("Example: holon-vc key setup --id issuer-key-1 --controller did:web:issuer.example")
        .subcommand(leaf("setup","Generate an encrypted signing key",&["id","controller"],&["algorithm","private-key","public-key"],&["force","password-stdin"]))
        .subcommand(leaf("inspect","Inspect public key metadata",&["key"],&[],&[]))
        .subcommand(leaf("export-public","Export a public verification method",&["key"],&["output"],&["force","password-stdin"]))
        .subcommand(leaf("rotate","Create a successor key and record rotation",&["key","id"],&[],&["password-stdin"]))
        .subcommand(leaf("list","List local public keys",&[],&[],&[])))
    .subcommand(Command::new("suite").about("Configure explicit cryptographic suites").subcommand_required(true).after_help("Example: holon-vc suite setup --name issuer-default --key holon-vc-data/keys/private/issuer-key-1.json --verification-method did:web:issuer.example#issuer-key-1")
        .subcommand(leaf("setup","Bind a key to a suite",&["name","key","verification-method"],&["cryptosuite","purpose"],&["legacy","force"]))
        .subcommand(leaf("inspect","Inspect a suite",&["name"],&[],&[])).subcommand(leaf("list","List suites",&[],&[],&[])))
    .subcommand(Command::new("trust").about("Manage scoped trust policies").subcommand_required(true).after_help("Example: holon-vc trust add --policy examples/trust-policy.json")
        .subcommand(leaf("add","Add a scoped issuer policy",&[],&["policy","issuer","verification-method","fingerprint","credential-type","schema","purpose","id"],&["force"]))
        .subcommand(leaf("remove","Remove a trust policy",&["id"],&[],&[])).subcommand(leaf("enable","Enable a policy",&["id"],&[],&[])).subcommand(leaf("disable","Disable a policy",&["id"],&[],&[])).subcommand(leaf("inspect","Inspect a policy",&["id"],&[],&[])).subcommand(leaf("list","List policies",&[],&[],&[])))
    .subcommand(Command::new("credential").about("Issue, disclose, and verify Holon credentials").subcommand_required(true).after_help("Example: holon-vc credential issue --holon examples/holon.json --schema schemas/holon-v1.schema.json --suite issuer-default --output holon.vc.json")
        .subcommand(leaf("issue","Validate and issue a Holon credential",&["holon"],&["schema","schema-id","suite","status-list","output","expires"],&["legacy","force","password-stdin"]))
        .subcommand(leaf("derive","Derive genuine selective disclosure without issuer keys",&["credential","reveal"],&["output","trust-store"],&["force"]))
        .subcommand(leaf("reissue-redacted","Issuer-controlled redacted reissuance with a new ID",&["credential","reveal"],&["suite","status-list","output"],&["force","password-stdin"]))
        .subcommand(leaf("verify","Verify cryptography, status, schema, evidence and trust",&["credential"],&["trust-store","output","threshold","conflicting-credential"],&["force","local-development"]))
        .subcommand(leaf("inspect","Inspect untrusted credential data without authenticating it",&["credential"],&[],&[])))
    .subcommand(Command::new("presentation").about("Create and verify signed or unsigned containers").subcommand_required(true).after_help("Example: holon-vc presentation verify --presentation signed.vp.json --challenge expected-nonce --domain verifier.example")
        .subcommand(leaf("create","Package credentials and optionally authenticate a holder",&["credential"],&["holder","suite","challenge","domain","expires","output"],&["sign","force","password-stdin"]))
        .subcommand(leaf("verify","Verify embedded credentials and holder authentication",&["presentation"],&["challenge","domain","trust-store","output","threshold"],&["force","local-development"]))
        .subcommand(leaf("inspect","Inspect an untrusted presentation",&["presentation"],&[],&[])))
    .subcommand(Command::new("status").about("Manage signed revocation and suspension lists").subcommand_required(true).after_help("Example: holon-vc status create --id issuer-status --url https://issuer.example/status --suite issuer-default")
        .subcommand(leaf("create","Create signed status lists",&["id","url"],&["suite","output"],&["force","password-stdin"]))
        .subcommand(leaf("revoke","Permanently revoke a credential",&["status-list","credential"],&["suite"],&["password-stdin"]))
        .subcommand(leaf("suspend","Suspend a credential",&["status-list","credential"],&["suite"],&["password-stdin"]))
        .subcommand(leaf("restore","Clear suspension; never undo revocation",&["status-list","credential"],&["suite"],&["password-stdin"]))
        .subcommand(leaf("inspect","Inspect a local status registry",&["status-list"],&[],&[])))
    .subcommand(Command::new("well-known").about("Generate and validate public discovery artefacts").subcommand_required(true).after_help("Example: holon-vc well-known generate --origin https://issuer.example --issuer-did did:web:issuer.example --suite issuer-default")
        .subcommand(leaf("generate","Stage public metadata and signed domain linkage",&["origin","issuer-did"],&["public-key","trust-policy","suite","output-dir","display-name"],&["jwks","openid","force","password-stdin"]))
        .subcommand(leaf("validate","Validate signatures, pins and metadata consistency",&["origin","issuer-did","expected-fingerprint"],&["output","output-dir"],&["force","local-development"]))
        .subcommand(leaf("inspect","Inspect a local publication manifest",&["output-dir"],&[],&[])))
}
pub fn get<'a>(m: &'a clap::ArgMatches, k: &str) -> Option<&'a str> {
    m.try_get_one::<String>(k)
        .ok()
        .flatten()
        .map(String::as_str)
}
pub fn yes(m: &clap::ArgMatches, k: &str) -> bool {
    m.try_get_one::<bool>(k)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}
