use std::{fs, path::Path};

const EXPECTED_CI_TOOLCHAIN: &str = "1.98.0";

fn workspace_file(path: &str) -> String {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(workspace.join(path)).unwrap_or_else(|error| {
        panic!("{path} must exist and be readable: {error}");
    })
}

fn ci_toolchain_contract_holds(ci: &str) -> bool {
    let selectors: Vec<_> = ci
        .lines()
        .filter_map(|line| {
            line.trim_start()
                .strip_prefix("- ")
                .unwrap_or(line.trim_start())
                .strip_prefix("uses: dtolnay/rust-toolchain@")
                .and_then(|selector| selector.split_whitespace().next())
        })
        .collect();
    let has_alternate_toolchain_input = ci.lines().map(str::trim_start).any(|line| {
        line.starts_with("toolchain:")
            || line.contains("rustup toolchain install")
            || line.contains("rustup default")
            || line.contains("rustup override set")
            || line.contains("rustup run")
    });

    selectors == [EXPECTED_CI_TOOLCHAIN]
        && !has_alternate_toolchain_input
        && ci.contains("cargo clippy --workspace --all-targets --all-features -- -D warnings")
}

#[test]
fn ci_toolchain_contract_rejects_duplicate_different_and_floating_selectors() {
    let good = "- uses: dtolnay/rust-toolchain@1.98.0\n- run: cargo clippy --workspace --all-targets --all-features -- -D warnings";
    let duplicate = format!("{good}\n- uses: dtolnay/rust-toolchain@1.98.0");
    let different = format!("{good}\n- uses: dtolnay/rust-toolchain@1.99.0");
    let floating = format!("{good}\n- uses: dtolnay/rust-toolchain@beta");
    let alternate_input = format!("{good}\n  toolchain: stable");
    let rustup_install = format!("{good}\n- run: rustup toolchain install stable");
    let rustup_default = format!("{good}\n- run: rustup default stable");
    let multiline_selector =
        format!("{good}\n- name: install a different Rust\n  uses: dtolnay/rust-toolchain@stable");
    let rustup_override = format!("{good}\n- run: rustup override set stable");
    let rustup_run = format!("{good}\n- run: rustup run stable cargo test");

    assert!(!ci_toolchain_contract_holds(&multiline_selector));
    assert!(!ci_toolchain_contract_holds(&duplicate));
    assert!(!ci_toolchain_contract_holds(&different));
    assert!(!ci_toolchain_contract_holds(&floating));
    assert!(!ci_toolchain_contract_holds(&alternate_input));
    assert!(!ci_toolchain_contract_holds(&rustup_install));
    assert!(!ci_toolchain_contract_holds(&rustup_default));
    assert!(!ci_toolchain_contract_holds(&rustup_override));
    assert!(!ci_toolchain_contract_holds(&rustup_run));
}

#[test]
fn rust_toolchain_contract_is_pinned_consistently_across_local_and_ci_builds() {
    let cargo: toml::Table = workspace_file("Cargo.toml")
        .parse()
        .expect("Cargo.toml must be valid TOML");
    let cargo_msrv = cargo
        .get("package")
        .and_then(|package| package.get("rust-version"))
        .and_then(toml::Value::as_str)
        .expect("Cargo.toml [package].rust-version must be set");

    let toolchain: toml::Table = workspace_file("rust-toolchain.toml")
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
    assert!(ci_toolchain_contract_holds(&ci));
}
