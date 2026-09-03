use std::path::PathBuf;
use std::process::Command;

#[test]
fn generic_sibling_cannot_access_host_platform_module() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let consumer = manifest_dir.join("tests/fixtures/platform_consumer.rs");
    let output = Command::new("rustc")
        .arg("--edition=2021")
        .arg(&consumer)
        .arg("-o")
        .arg(manifest_dir.join("target/platform-consumer-test"))
        .output()
        .expect("rustc must be available for the compile-fail boundary test");

    assert!(
        !output.status.success(),
        "platform consumer unexpectedly compiled"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("is private"),
        "expected a host platform privacy error, got:\n{stderr}"
    );
}

#[test]
fn generic_consumer_cannot_forge_or_leak_dedicated_account_proofs() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture =
        std::fs::read_to_string(manifest_dir.join("tests/fixtures/dedicated_account_consumer.rs"))
            .unwrap();
    let platform = manifest_dir
        .join("src/platform/mod.rs")
        .to_string_lossy()
        .replace('\\', "\\\\");
    let root = std::env::temp_dir().join(format!(
        "styrn-dedicated-account-boundary-{}-{}",
        std::process::id(),
        uuid::Uuid::now_v7()
    ));
    let source = root.join("src");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        r#"[package]
name = "dedicated-account-boundary"
version = "0.0.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
sha2 = "0.11"
uuid = { version = "1.26", features = ["v7", "serde"] }
libc = "=0.2.189"
"#,
    )
    .unwrap();
    std::fs::write(
        source.join("main.rs"),
        fixture.replace("__PLATFORM_PATH__", &platform),
    )
    .unwrap();

    let output = Command::new("cargo")
        .arg("check")
        .arg("--offline")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(root.join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", root.join("target"))
        .output()
        .expect("cargo must be available for the compile-fail boundary test");
    std::fs::remove_dir_all(&root).unwrap();

    assert!(
        !output.status.success(),
        "dedicated account consumer unexpectedly compiled"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    for expected in [
        "DedicatedAccountHandle` doesn't implement `Debug",
        "DedicatedAccountHandle: serde::Serialize` is not satisfied",
        "EstablishedDedicatedAccountEvidence: serde::Serialize` is not satisfied",
        "field `0` of struct `DedicatedAccountHandle` is private",
        "field `selector` of struct `EstablishedDedicatedAccountEvidence` is private",
        "tuple struct constructor `DedicatedAccountFactoryAuthority` is private",
        "method `reverify_and_bind` is private",
    ] {
        assert!(
            stderr.contains(expected),
            "expected compile failure containing {expected:?}, got:\n{stderr}"
        );
    }
}
