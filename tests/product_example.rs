#[test]
fn product_credential_workflow() {
    let status = std::process::Command::new("python3")
        .args([
            "scripts/product-workflow.py",
            "--binary",
            env!("CARGO_BIN_EXE_holon-vc"),
        ])
        .status()
        .expect("Python 3 runs the product credential example");
    assert!(status.success());
}
