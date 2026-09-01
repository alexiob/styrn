#[allow(dead_code)]
#[path = "../src/output/mod.rs"]
mod output;

mod fixture_builder;

use jsonschema::Validator;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

const EXPECTED_REGISTRY: [(&str, i32); 37] = [
    ("usage.invalid_argument", 2),
    ("usage.config_invalid", 2),
    ("transport.unreachable", 3),
    ("transport.auth_failed", 4),
    ("transport.session_lost", 3),
    ("protocol.incompatible", 8),
    ("protocol.malformed", 8),
    ("machine.manifest_invalid", 2),
    ("resource.memory_admission_denied", 6),
    ("resource.cpu_admission_denied", 6),
    ("resource.disk_admission_denied", 6),
    ("resource.heavy_exclusivity_denied", 6),
    ("resource.job_disk_limit_exceeded", 12),
    ("resource.host_disk_floor", 12),
    ("capability.unsatisfied", 7),
    ("job.not_found", 2),
    ("job.timeout", 10),
    ("job.cancelled", 12),
    ("job.workflow_failed", 12),
    ("job.supervisor_lost", 12),
    ("agent.not_found", 2),
    ("agent.harness_error", 11),
    ("project.profile_invalid", 2),
    ("project.workflow_not_declared", 2),
    ("project.revision_unresolved", 2),
    ("project.worktree_dirty", 2),
    ("fleet.partial", 9),
    ("internal.error", 1),
    ("setup.probe_failed", 13),
    ("setup.plan_invalid", 13),
    ("setup.confirmation_required", 13),
    ("setup.elevation_required", 13),
    ("setup.apply_failed", 13),
    ("setup.needs_human", 13),
    ("setup.unsupported_os", 13),
    ("setup.receipt_conflict", 13),
    ("setup.adopt_mismatch", 13),
];

const EXPECTED_EXITS: [i32; 14] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];

fn validator() -> Validator {
    let schema: Value = serde_json::from_str(
        &fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/schemas/command-v1.schema.json"
        ))
        .unwrap(),
    )
    .unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

fn assert_schema_valid(value: &Value) {
    let validator = validator();
    let errors = validator
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    if !errors.is_empty() {
        panic!(
            "envelope must validate against schemas/command-v1.schema.json:\n{}",
            errors.join("\n")
        );
    }
}

#[test]
fn registry_is_exactly_the_documented_append_only_set() {
    let actual: Vec<(&str, i32)> = output::ErrorCode::ALL
        .iter()
        .map(|code| (code.as_str(), code.exit_code().as_i32()))
        .collect();

    assert_eq!(actual, EXPECTED_REGISTRY);
}

#[test]
fn typed_exit_table_produces_every_documented_process_status() {
    let fixture = fixture();
    let actual: Vec<i32> = output::StyrnExit::ALL
        .iter()
        .map(|exit| exit.as_i32())
        .collect();

    assert_eq!(actual, EXPECTED_EXITS);

    for exit in output::StyrnExit::ALL {
        let code = exit.as_i32();
        let output = run_fixture(fixture, &["exit", &code.to_string()]);
        assert_eq!(output.status.code(), Some(code), "exit {code}");
        assert!(output.stdout.is_empty(), "exit {code} wrote stdout");
        assert!(output.stderr.is_empty(), "exit {code} wrote stderr");
    }
}

#[test]
fn every_registry_entry_resolves_to_its_documented_process_status() {
    let fixture = fixture();

    for (name, exit_code) in EXPECTED_REGISTRY {
        let output = run_fixture(fixture, &["registry", name]);
        assert_eq!(output.status.code(), Some(exit_code), "{name}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("{name} {exit_code}\n"),
            "{name}"
        );
        assert!(output.stderr.is_empty(), "{name} wrote stderr");
    }
}

#[test]
fn workflow_inner_exit_is_preserved_in_json_but_never_becomes_the_process_exit() {
    let fixture = fixture();
    let output = run_fixture(fixture, &["workflow-101"]);

    assert_eq!(output.status.code(), Some(12));
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["ok"], false);
    assert_eq!(value["command"], "workflow run");
    assert_eq!(value["errors"][0]["code"], "job.workflow_failed");
    assert_eq!(value["data"]["exit_code"], 101);
    assert_schema_valid(&value);
}

#[test]
fn exec_remote_exit_is_mirrored_and_remains_explicit_in_json() {
    let fixture = fixture();
    let output = run_fixture(fixture, &["exec-101"]);

    assert_eq!(output.status.code(), Some(101));
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(value["command"], "exec");
    assert_eq!(value["data"]["exit_code"], 101);
    assert_schema_valid(&value);
}

#[test]
fn unmapped_panic_becomes_internal_error_with_exit_one() {
    let fixture = fixture();
    let output = run_fixture(fixture, &["panic"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["ok"], false);
    assert_eq!(value["errors"][0]["code"], "internal.error");
    assert_eq!(value["data"], Value::Null);
    assert_schema_valid(&value);
}

fn run_fixture(fixture: &Path, args: &[&str]) -> Output {
    Command::new(fixture).args(args).output().unwrap()
}

fn fixture() -> &'static PathBuf {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE.get_or_init(|| fixture_builder::build_example("outcome-fixture-test"))
}
