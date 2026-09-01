use std::{fs, path::Path};

fn workspace_file(path: &str) -> String {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(workspace.join(path)).unwrap_or_else(|error| {
        panic!("{path} must exist and be readable: {error}");
    })
}

#[test]
fn rust_toolchain_contract_is_pinned_consistently_across_local_and_ci_builds() {
    let cargo: toml::Value = workspace_file("Cargo.toml")
        .parse()
        .expect("Cargo.toml must be valid TOML");
    let cargo_msrv = cargo
        .get("package")
        .and_then(|package| package.get("rust-version"))
        .and_then(toml::Value::as_str)
        .expect("Cargo.toml [package].rust-version must be set");

    let toolchain: toml::Value = workspace_file("rust-toolchain.toml")
        .parse()
        .expect("rust-toolchain.toml must be valid TOML");
    let toolchain_config = toolchain
        .get("toolchain")
        .expect("rust-toolchain.toml [toolchain] table must be set");
    let channel = toolchain_config
        .get("channel")
        .and_then(toml::Value::as_str)
        .expect("rust-toolchain.toml [toolchain].channel must be set");
    let profile = toolchain_config
        .get("profile")
        .and_then(toml::Value::as_str)
        .expect("rust-toolchain.toml [toolchain].profile must be set");
    let components = toolchain_config
        .get("components")
        .and_then(toml::Value::as_array)
        .expect("rust-toolchain.toml [toolchain].components must be an array");
    let components: Vec<_> = components.iter().filter_map(toml::Value::as_str).collect();

    assert_eq!(cargo_msrv, "1.98");
    assert_eq!(channel, "1.98.0");
    assert_eq!(profile, "minimal");
    assert!(components.contains(&"rustfmt"));
    assert!(components.contains(&"clippy"));

    let ci = workspace_file(".github/workflows/ci.yml");
    assert!(
        ci.contains("dtolnay/rust-toolchain@1.98.0"),
        "CI must select the exact project toolchain rather than a floating channel"
    );
    assert!(
        !ci.contains("dtolnay/rust-toolchain@stable"),
        "CI must not retain a floating Rust toolchain selector"
    );
    assert!(
        ci.contains("cargo clippy --workspace --all-targets --all-features -- -D warnings"),
        "CI must exercise the pinned clippy component with warnings denied"
    );
}
