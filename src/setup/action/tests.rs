use super::{
    Action, ActionDescription, ActionEffect, ActionError, ActionName, ApplyOutcome,
    HumanInstructions, NeedsHuman, Privilege, TestMetrics,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn state_driven(state: Arc<Mutex<Vec<u8>>>) -> (Action, TestMetrics) {
    Action::test_state_driven(Privilege::None, state)
}

#[test]
fn done_check_returns_noop_without_running_mutation_or_changing_bytes() {
    let state = Arc::new(Mutex::new(vec![1]));
    let before = state.lock().unwrap().clone();
    let (mut action, metrics) = state_driven(Arc::clone(&state));

    let outcome = action
        .apply()
        .expect("done check must be a successful no-op");

    assert_eq!(outcome, ApplyOutcome::Noop);
    assert_eq!(metrics.check_calls(), 1);
    assert_eq!(metrics.mutation_calls(), 0);
    assert_eq!(*state.lock().unwrap(), before);
}

#[test]
fn todo_check_runs_mutation_once_then_a_second_public_apply_is_a_noop() {
    let state = Arc::new(Mutex::new(vec![0]));
    let (mut action, metrics) = state_driven(Arc::clone(&state));

    assert_eq!(
        action.apply().unwrap(),
        ApplyOutcome::Applied(ActionEffect::Changed)
    );
    assert_eq!(action.apply().unwrap(), ApplyOutcome::Noop);

    assert_eq!(*state.lock().unwrap(), vec![1]);
    assert_eq!(metrics.check_calls(), 2);
    assert_eq!(metrics.mutation_calls(), 1);
}

#[test]
fn needs_human_is_not_mutated_or_reported_as_success() {
    let state = Arc::new(Mutex::new(vec![0]));
    let needs_human = NeedsHuman::new(
        HumanInstructions::new("Sign in to the local account before continuing.").unwrap(),
        None,
    );
    let (mut action, metrics) =
        Action::test_needs_human(Privilege::Admin, Arc::clone(&state), needs_human.clone());

    assert_eq!(
        action.apply().unwrap(),
        ApplyOutcome::NeedsHuman(needs_human)
    );
    assert_eq!(*state.lock().unwrap(), vec![0]);
    assert_eq!(metrics.mutation_calls(), 0);
}

#[test]
fn unsafe_human_text_is_rejected_without_echoing_the_rejected_value() {
    let secret = "sk_live_do-not-echo";
    let name_error = ActionName::parse(secret).unwrap_err();
    let description_error = ActionDescription::new(secret).unwrap_err();
    let instruction_error = HumanInstructions::new(secret).unwrap_err();

    assert_eq!(name_error, ActionError::InvalidActionName);
    assert_eq!(description_error, ActionError::InvalidDescription);
    assert_eq!(instruction_error, ActionError::InvalidInstructions);
    assert_eq!(
        HumanInstructions::new("").unwrap_err(),
        ActionError::InvalidInstructions
    );
    for error in [name_error, description_error, instruction_error] {
        assert!(!error.to_string().contains(secret));
    }
    assert_eq!(
        ActionName::parse("Test.invalid").unwrap_err(),
        ActionError::InvalidActionName
    );
}

#[test]
fn check_and_apply_failures_are_typed_safe_and_have_no_success_outcome() {
    let secret = "ghp_do-not-echo";
    let check_state = Arc::new(Mutex::new(vec![0]));
    let (mut check_failure, check_metrics) =
        Action::test_check_failure(Privilege::None, Arc::clone(&check_state));
    let apply_state = Arc::new(Mutex::new(vec![0]));
    let (mut apply_failure, apply_metrics) =
        Action::test_apply_failure(Privilege::Root, Arc::clone(&apply_state));

    let check_error = check_failure.apply().unwrap_err();
    let apply_error = apply_failure.apply().unwrap_err();

    assert!(matches!(check_error, ActionError::CheckFailed { .. }));
    assert!(matches!(apply_error, ActionError::ApplyFailed { .. }));
    for error in [check_error, apply_error] {
        assert!(error.to_string().contains("test.state"));
        assert!(!error.to_string().contains(secret));
    }
    assert_eq!(check_metrics.mutation_calls(), 0);
    assert_eq!(apply_metrics.mutation_calls(), 1);
    assert_eq!(*check_state.lock().unwrap(), vec![0]);
    assert_eq!(*apply_state.lock().unwrap(), vec![0]);
}

#[test]
fn deterministic_privilege_and_description_cover_all_platform_needs() {
    let state = Arc::new(Mutex::new(vec![1]));
    let actions = [
        Action::test_state_driven(Privilege::None, Arc::clone(&state)).0,
        Action::test_state_driven(Privilege::Root, Arc::clone(&state)).0,
        Action::test_state_driven(Privilege::Admin, state).0,
    ];

    assert_eq!(
        actions
            .iter()
            .map(|action| action.privilege())
            .collect::<Vec<_>>(),
        vec![Privilege::None, Privilege::Root, Privilege::Admin]
    );
    assert!(actions
        .iter()
        .all(|action| action.describe().as_str() == "Converge test state"));
}

#[test]
fn foundation_action_phase_seven_slots_return_typed_unsupported_errors() {
    let state = Arc::new(Mutex::new(vec![1]));
    let mut action = state_driven(state).0;

    assert!(matches!(
        action.revert(&ActionEffect::Changed),
        Err(ActionError::UnsupportedUntilPhase7 { action, operation: super::UnsupportedOperation::Revert }) if action.as_str() == "test.state"
    ));
    assert!(matches!(
        action.render_posix(),
        Err(ActionError::UnsupportedUntilPhase7 { action, operation: super::UnsupportedOperation::RenderPosix }) if action.as_str() == "test.state"
    ));
    assert!(matches!(
        action.render_powershell(),
        Err(ActionError::UnsupportedUntilPhase7 { action, operation: super::UnsupportedOperation::RenderPowerShell }) if action.as_str() == "test.state"
    ));
}

#[test]
fn script_fragments_reject_raw_shell_text_at_the_type_boundary() {
    assert_fixture_fails(
        "raw_script_fragment.rs",
        FixtureExpectation::new(
            "E0308",
            "mismatched types",
            7,
            Some("expected `ActionName`, found `String`"),
            "raw_script_fragment.rs",
        ),
    );
}

#[test]
fn script_fragment_variants_remain_closed_to_typed_data() {
    assert_fixture_compiles("script_fragment_variants.rs");
}

#[test]
fn ordinary_callers_cannot_invoke_the_ungated_mutation_hook() {
    assert_fixture_fails(
        "ungated_mutation.rs",
        FixtureExpectation::new(
            "E0599",
            "no method named `apply_mutation` found for mutable reference `&mut action::Action` in the current scope",
            7,
            Some("method not found in `&mut action::Action`"),
            "ungated_mutation.rs",
        ),
    );
}

#[test]
fn an_outside_module_cannot_unseal_an_action_implementation() {
    assert_fixture_fails(
        "unsealed_action.rs",
        FixtureExpectation::new(
            "E0404",
            "expected trait, found enum `Action`",
            10,
            Some("not a trait"),
            "unsealed_action.rs",
        ),
    );
}

#[test]
fn a_setup_owned_descendant_cannot_invoke_the_gate_executor_directly() {
    assert_fixture_fails_with_cfg(
        "owned_descendant.rs",
        &["action_owned_descendant_fixture"],
        FixtureExpectation::new(
            "E0603",
            "function `execute` is private",
            2,
            Some("private function"),
            "owned_descendant_impl.rs",
        ),
    );
}

#[derive(Clone, Copy)]
struct FixtureExpectation {
    code: &'static str,
    message: &'static str,
    line: u64,
    primary_label: Option<&'static str>,
    source_name: &'static str,
}

impl FixtureExpectation {
    const fn new(
        code: &'static str,
        message: &'static str,
        line: u64,
        primary_label: Option<&'static str>,
        source_name: &'static str,
    ) -> Self {
        Self {
            code,
            message,
            line,
            primary_label,
            source_name,
        }
    }
}

fn assert_fixture_fails(name: &str, expected: FixtureExpectation) {
    assert_fixture_fails_with_cfg(name, &[], expected);
}

fn assert_fixture_compiles(name: &str) {
    let output = compile_fixture(name, &[]);
    assert!(
        output.status.success(),
        "{name} must compile while ScriptFragment has only typed variants: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{name} must compile without warnings: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_fixture_fails_with_cfg(
    name: &str,
    configurations: &[&str],
    expected: FixtureExpectation,
) {
    let output = compile_fixture(name, configurations);
    assert!(
        !output.status.success(),
        "{name} unexpectedly compiled as an action-boundary bypass"
    );
    let diagnostics = String::from_utf8(output.stderr)
        .expect("rustc diagnostics must be valid UTF-8")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(
        diagnostics
            .iter()
            .all(|diagnostic| diagnostic["level"] != "warning"),
        "{name} must not rely on warning diagnostics: {diagnostics:#?}"
    );
    let errors = diagnostics
        .iter()
        .filter(|diagnostic| diagnostic["level"] == "error" && !diagnostic["code"].is_null())
        .collect::<Vec<_>>();
    assert_eq!(
        errors.len(),
        1,
        "{name} must have exactly one causal coded error: {diagnostics:#?}"
    );
    let error = errors[0];
    assert_eq!(error["code"]["code"], expected.code);
    assert_eq!(error["message"], expected.message);
    assert!(
        error["spans"].as_array().unwrap().iter().any(|span| {
            span["is_primary"] == true
                && span["file_name"]
                    .as_str()
                    .is_some_and(|file| file.ends_with(expected.source_name))
                && span["line_start"] == expected.line
                && span["label"].as_str() == expected.primary_label
        }),
        "unexpected primary span: {error:#?}"
    );
}

fn compile_fixture(name: &str, configurations: &[&str]) -> Output {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let artifacts = CargoArtifacts::build(&manifest_dir);
    let fixture = manifest_dir.join("src/setup/action/fixtures").join(name);
    let output = FixtureOutput::new();
    let mut command = Command::new("rustc");
    command
        .arg("--edition=2021")
        .arg("--error-format=json")
        .arg(fixture)
        .arg("-L")
        .arg(format!("dependency={}", artifacts.deps_dir.display()));
    if configurations.contains(&"test") {
        command.arg("--test");
    }
    for configuration in configurations {
        command.arg("--cfg").arg(configuration);
    }
    for dependency in ["base64", "serde", "serde_json", "thiserror"] {
        command.arg("--extern").arg(format!(
            "{dependency}={}",
            artifacts.paths[dependency].display()
        ));
    }
    command
        .arg("-o")
        .arg(&output.path)
        .output()
        .expect("rustc must be available for compile-fail boundary tests")
}

struct CargoArtifacts {
    deps_dir: PathBuf,
    paths: BTreeMap<String, PathBuf>,
    _target: FixtureTarget,
}

impl CargoArtifacts {
    fn build(manifest_dir: &Path) -> Self {
        let target = FixtureTarget::new();
        let output = Command::new("cargo")
            .current_dir(manifest_dir)
            .args([
                "build",
                "--locked",
                "--message-format=json-render-diagnostics",
                "--target-dir",
            ])
            .arg(&target.path)
            .output()
            .expect("cargo must be available for compile-fail boundary tests");
        assert!(
            output.status.success(),
            "Cargo dependency build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut paths = BTreeMap::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let Some(name) = message["target"]["name"].as_str() else {
                continue;
            };
            if !["base64", "serde", "serde_json", "thiserror"].contains(&name) {
                continue;
            }
            let artifact = message["filenames"].as_array().and_then(|filenames| {
                filenames
                    .iter()
                    .filter_map(|filename| filename.as_str())
                    .find(|filename| filename.ends_with(".rlib"))
            });
            if let Some(artifact) = artifact {
                paths.insert(name.to_owned(), PathBuf::from(artifact));
            }
        }
        for dependency in ["base64", "serde", "serde_json", "thiserror"] {
            assert!(
                paths.contains_key(dependency),
                "Cargo did not report a {dependency} library artifact"
            );
        }
        Self {
            deps_dir: target.path.join("debug/deps"),
            paths,
            _target: target,
        }
    }
}

struct FixtureTarget {
    path: PathBuf,
}

impl FixtureTarget {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        Self {
            path: std::env::temp_dir().join(format!(
                "styrn-action-fixture-target-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )),
        }
    }
}

impl Drop for FixtureTarget {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct FixtureOutput {
    path: PathBuf,
}

impl FixtureOutput {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        Self {
            path: std::env::temp_dir().join(format!(
                "styrn-action-fixture-output-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )),
        }
    }
}

impl Drop for FixtureOutput {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
