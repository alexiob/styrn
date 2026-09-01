#[allow(dead_code)]
#[path = "../src/output/mod.rs"]
mod output;

mod fixture_builder;

use chrono::{TimeZone, Utc};
use jsonschema::Validator;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

fn timestamp() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 1, 12, 0, 0).single().unwrap()
}

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
fn success_envelope_is_schema_valid_and_has_the_stable_shape() {
    let envelope = output::Envelope::success(
        "project status",
        timestamp(),
        json!({"ready": true}),
        vec![output::Diagnostic::new("project.stale", "refresh recommended", None).unwrap()],
    )
    .unwrap();

    let json = output::to_json(&envelope).unwrap();
    let value: Value = serde_json::from_str(&json).unwrap();

    assert_eq!(
        value,
        json!({
            "schema": "styrn.command.v1",
            "ok": true,
            "command": "project status",
            "timestamp": "2026-09-01T12:00:00Z",
            "data": {"ready": true},
            "warnings": [{"code": "project.stale", "message": "refresh recommended"}],
            "errors": []
        })
    );
    assert_schema_valid(&value);
}

#[test]
fn failure_envelope_is_schema_valid_with_null_data_and_a_structured_error() {
    let envelope = output::Envelope::failure(
        "project status",
        timestamp(),
        vec![output::ErrorDiagnostic::new(
            output::ErrorCode::ProjectProfileInvalid,
            "project is unavailable",
            Some(json!({"project_id": "p-1"})),
        )
        .unwrap()],
        vec![],
    )
    .unwrap();

    let value: Value = serde_json::from_str(&output::to_json(&envelope).unwrap()).unwrap();

    assert_eq!(value["ok"], false);
    assert_eq!(value["data"], Value::Null);
    assert_eq!(
        value["errors"],
        json!([{
            "code": "project.profile_invalid",
            "message": "project is unavailable",
            "details": {"project_id": "p-1"}
        }])
    );
    assert_schema_valid(&value);
}

#[test]
fn invalid_envelope_inputs_are_rejected_before_serialization() {
    assert!(output::Envelope::success("", timestamp(), json!({}), vec![]).is_err());
    assert!(
        output::Envelope::success("project status", timestamp(), json!("not allowed"), vec![])
            .is_err()
    );
    assert!(output::Envelope::failure("project status", timestamp(), vec![], vec![]).is_err());
    assert!(output::Diagnostic::new("not_namespaced", "bad code", None).is_err());
}

#[test]
fn fixture_writes_one_schema_valid_json_document_to_stdout_and_diagnostics_to_stderr() {
    let output = Command::new(fixture()).output().unwrap();

    assert!(output.status.success());
    assert!(
        !output.stderr.is_empty(),
        "fixture must write a diagnostic to stderr"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: Value = serde_json::from_str(&stdout)
        .expect("stdout must be exactly one JSON document with no trailing decoration");
    assert_schema_valid(&value);
}

fn fixture() -> &'static PathBuf {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE.get_or_init(|| fixture_builder::build_example("output-fixture-test"))
}
