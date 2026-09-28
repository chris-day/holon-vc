use holon_vc::cli;
#[test]
fn all_help_paths() {
    let command = cli::command();
    command.clone().debug_assert();
    for group in command.get_subcommands() {
        let name = group.get_name();
        assert_eq!(
            cli::command()
                .try_get_matches_from(["holon-vc", name, "--help"])
                .unwrap_err()
                .kind(),
            clap::error::ErrorKind::DisplayHelp
        );
        assert_eq!(
            cli::command()
                .try_get_matches_from(["holon-vc", "help", name])
                .unwrap_err()
                .kind(),
            clap::error::ErrorKind::DisplayHelp
        );
        for leaf in group.get_subcommands() {
            let sub = leaf.get_name();
            for args in [
                vec!["holon-vc", name, sub, "--help"],
                vec!["holon-vc", "help", name, sub],
            ] {
                assert_eq!(
                    cli::command()
                        .try_get_matches_from(args)
                        .unwrap_err()
                        .kind(),
                    clap::error::ErrorKind::DisplayHelp
                );
            }
        }
    }
    assert_eq!(
        cli::command()
            .try_get_matches_from(["holon-vc", "--version"])
            .unwrap_err()
            .kind(),
        clap::error::ErrorKind::DisplayVersion
    );
}
#[test]
fn passwords_not_arguments() {
    assert!(
        cli::command()
            .try_get_matches_from([
                "holon-vc",
                "key",
                "setup",
                "--id",
                "x",
                "--controller",
                "did:web:example.org",
                "--password",
                "secret"
            ])
            .is_err()
    );
}
#[test]
fn binary_output_and_exit_contract() {
    let bin = env!("CARGO_BIN_EXE_holon-vc");
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let json = std::process::Command::new(bin)
        .args([
            "--data-dir",
            root.to_str().unwrap(),
            "--output-format",
            "json",
            "key",
            "list",
        ])
        .output()
        .unwrap();
    assert!(json.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&json.stdout).unwrap(),
        serde_json::json!([])
    );
    assert!(json.stderr.is_empty());
    let usage = std::process::Command::new(bin)
        .args(["credential", "verify", "--threshold", "unknown"])
        .output()
        .unwrap();
    assert_eq!(usage.status.code(), Some(2));
    let bad = dir.path().join("bad.json");
    std::fs::write(&bad, b"{\"secret\":1,\"secret\":2}").unwrap();
    let output = std::process::Command::new(bin)
        .args([
            "--data-dir",
            root.to_str().unwrap(),
            "--output-format",
            "json",
            "credential",
            "verify",
            "--credential",
            bad.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let error: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(error["error"]["code"], "INVALID_JSON");
    assert!(!String::from_utf8(output.stdout).unwrap().contains("secret"));
    let human = std::process::Command::new(bin)
        .args([
            "--data-dir",
            root.to_str().unwrap(),
            "--output-format",
            "human",
            "credential",
            "verify",
            "--credential",
            bad.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(human.stdout.is_empty());
    assert!(!human.stderr.is_empty());
}
