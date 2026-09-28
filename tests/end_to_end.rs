#[test]
fn documented_cli_workflow() {
    let status = std::process::Command::new("python3")
        .args([
            "scripts/workflow.py",
            "--binary",
            env!("CARGO_BIN_EXE_holon-vc"),
        ])
        .status()
        .expect("Python 3 runs executable documentation");
    assert!(status.success());
}
