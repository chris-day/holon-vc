#[tokio::main(flavor = "current_thread")]
async fn main() {
    use holon_vc::{app, cli, storage};
    let matches = cli::command().get_matches();
    let json = cli::get(&matches, "output-format") == Some("json");
    let quiet = cli::yes(&matches, "quiet");
    let level = if quiet {
        "off"
    } else if cli::yes(&matches, "verbose") {
        "info"
    } else {
        "warn"
    };
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(level)
        .try_init();
    let result = async {
        let mut app = app::App::new(&matches)?;
        let _lock = storage::lock(&app.root)?;
        let (group, m) = matches.subcommand().expect("required command");
        let (action, m) = m.subcommand().expect("required action");
        tracing::info!(command = group, action, "Starting operation");
        let value = app::run(&mut app, group, action, m).await?;
        app::output(m, &value)?;
        let code = if action == "verify" || action == "validate" {
            let r: holon_vc::reports::VerificationReport = serde_json::from_value(value.clone())
                .map_err(|_| {
                    holon_vc::errors::error("INTERNAL", "report", "Invalid internal report")
                })?;
            if r.accepted(cli::get(m, "threshold").unwrap_or("authentic-assertion")) {
                0
            } else if r.errors.iter().any(|s| s.contains("UNAVAILABLE")) {
                7
            } else if ["rejected", "disputed"].contains(&r.decision.as_str()) {
                5
            } else {
                6
            }
        } else {
            0
        };
        tracing::info!(
            command = group,
            action,
            exit_code = code,
            "Operation finished"
        );
        Ok::<_, holon_vc::errors::Error>((value, code))
    }
    .await;
    match result {
        Ok((value, code)) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).expect("JSON value")
                );
            } else if let Some(decision) = value["decision"].as_str() {
                println!("Decision: {decision}");
                println!(
                    "Cryptography: {} | Issuer authenticated: {} | Trusted: {} | Status: {}",
                    value["cryptographicallyValid"],
                    value["issuerAuthenticated"],
                    value["issuerTrustedForClaimType"],
                    value["status"].as_str().unwrap_or("unavailable")
                );
                for e in value["errors"].as_array().into_iter().flatten() {
                    println!("Error: {}", e.as_str().unwrap_or("verification failed"));
                }
                if !quiet {
                    for w in value["warnings"].as_array().into_iter().flatten() {
                        println!("Warning: {}", w.as_str().unwrap_or(""));
                    }
                }
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).expect("JSON value")
                );
            }
            if code != 0 {
                std::process::exit(code);
            }
        }
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({"error":e}));
            } else {
                eprintln!("{e}");
            }
            let code = if e.code.contains("UNAVAILABLE") {
                7
            } else if e.stage == "storage" || e.stage == "key-storage" {
                8
            } else if e.code.starts_with("UNSUPPORTED") {
                4
            } else if e.code == "INTERNAL" {
                9
            } else {
                3
            };
            std::process::exit(code);
        }
    }
}
