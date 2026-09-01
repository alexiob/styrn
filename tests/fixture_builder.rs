use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

pub fn build_example(name: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new(cargo_path())
        .current_dir(&manifest_dir)
        .env(
            "CARGO_TARGET_DIR",
            manifest_dir.join("target/fixture-examples"),
        )
        .args([
            "build",
            "--quiet",
            "--locked",
            "--offline",
            "--example",
            name,
            "--message-format=json-render-diagnostics",
        ])
        .output()
        .expect("Cargo must be available to build the fixture example");

    assert!(
        output.status.success(),
        "fixture example {name} must build:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "fixture example {name} build must not emit stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    compiler_artifact_path(name, &output.stdout).unwrap_or_else(|| {
        panic!(
            "Cargo did not report an executable for fixture example {name}:\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn cargo_path() -> PathBuf {
    std::env::var_os("CARGO")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("cargo"))
}

fn compiler_artifact_path(name: &str, stdout: &[u8]) -> Option<PathBuf> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find_map(|message| {
            (message["reason"] == "compiler-artifact"
                && message["target"]["name"] == name
                && message["target"]["kind"]
                    .as_array()
                    .is_some_and(|kinds| kinds.iter().any(|kind| kind == "example")))
            .then(|| message["executable"].as_str().map(PathBuf::from))
            .flatten()
        })
}
