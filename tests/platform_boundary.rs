use std::path::PathBuf;
use std::process::Command;

#[test]
fn generic_consumer_cannot_access_platform_module() {
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
        stderr.contains("module `platform` is private"),
        "expected a platform privacy error, got:\n{stderr}"
    );
}
