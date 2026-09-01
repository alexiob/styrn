use jsonschema::JSONSchema;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use uuid::Uuid;

#[test]
fn manifest_json_repairs_once_and_keeps_a_stable_schema_valid_id() {
    let temp = TestDir::new();
    fs::write(
        temp.path().join("machine.toml"),
        remove_line(
            &fs::read_to_string("examples/machine.toml").unwrap(),
            "machine_id =",
        ),
    )
    .unwrap();

    let first = run(temp.path(), &["machine", "manifest", "--json"]);
    assert!(first.status.success(), "{first:?}");
    let first_json = exactly_one_json(&first.stdout);
    assert_schema_valid(&first_json);
    assert_eq!(first_json["ok"], true);
    assert_eq!(first_json["command"], "machine manifest");
    assert_eq!(first_json["warnings"].as_array().unwrap().len(), 1);
    assert_eq!(
        first_json["warnings"][0]["code"],
        "machine.machine_id_minted"
    );

    let second = run(temp.path(), &["machine", "manifest", "--json"]);
    assert!(second.status.success(), "{second:?}");
    let second_json = exactly_one_json(&second.stdout);
    assert_schema_valid(&second_json);
    assert_eq!(second_json["warnings"].as_array().unwrap().len(), 0);
    assert_eq!(
        second_json["data"]["machine_id"],
        first_json["data"]["machine_id"]
    );
}

#[test]
fn init_and_manifest_report_invalid_documents_as_one_typed_exit_two_envelope() {
    let temp = TestDir::new();
    fs::write(
        temp.path().join("machine.toml"),
        "schema_version = 1\nname = 'bad'\n",
    )
    .unwrap();

    for arguments in [
        ["machine", "manifest", "--json"],
        ["machine", "init", "--json"],
    ] {
        let output = run(temp.path(), &arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}: {output:?}");
        let json = exactly_one_json(&output.stdout);
        assert_schema_valid(&json);
        assert_eq!(json["ok"], false);
        assert_eq!(json["data"], Value::Null);
        assert_eq!(json["errors"].as_array().unwrap().len(), 1);
        assert_eq!(json["errors"][0]["code"], "machine.manifest_invalid");
    }
}

#[test]
fn init_repairs_an_existing_stage_zero_manifest_but_never_invents_one() {
    let repaired_dir = TestDir::new();
    fs::write(
        repaired_dir.path().join("machine.toml"),
        remove_line(
            &fs::read_to_string("examples/machine.toml").unwrap(),
            "machine_id =",
        ),
    )
    .unwrap();
    let repaired = run(repaired_dir.path(), &["machine", "init", "--json"]);
    assert!(repaired.status.success(), "{repaired:?}");
    let repaired_json = exactly_one_json(&repaired.stdout);
    assert_eq!(repaired_json["command"], "machine init");
    assert_eq!(
        repaired_json["warnings"][0]["code"],
        "machine.machine_id_minted"
    );
    assert!(repaired_dir.path().join("machine.toml").exists());

    let absent_dir = TestDir::new();
    let absent = run(absent_dir.path(), &["machine", "init", "--json"]);
    assert_eq!(absent.status.code(), Some(2));
    let absent_json = exactly_one_json(&absent.stdout);
    assert_eq!(absent_json["errors"][0]["code"], "machine.manifest_invalid");
    assert!(!absent_dir.path().join("machine.toml").exists());
}

fn run(config_dir: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_styrn"))
        .args(arguments)
        .env("STYRN_CONFIG_DIR", config_dir)
        .output()
        .unwrap()
}

fn exactly_one_json(stdout: &[u8]) -> Value {
    assert!(!stdout.is_empty());
    serde_json::from_slice(stdout).unwrap()
}

fn schema_validator() -> JSONSchema {
    let schema: Value = serde_json::from_str(
        &fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/schemas/command-v1.schema.json"
        ))
        .unwrap(),
    )
    .unwrap();
    JSONSchema::compile(&schema).unwrap()
}

fn assert_schema_valid(value: &Value) {
    if let Err(errors) = schema_validator().validate(value) {
        panic!(
            "command JSON must validate against the checked-in schema:\n{}",
            errors
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

fn remove_line(input: &str, starts_with: &str) -> String {
    input
        .lines()
        .filter(|line| !line.trim_start().starts_with(starts_with))
        .collect::<Vec<_>>()
        .join("\n")
}

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("styrn-machine-cli-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
