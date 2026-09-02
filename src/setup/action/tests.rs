use super::{
    apply_plan_with_journal, Action, ActionDescription, ActionEffect, ActionError, ActionName,
    ApplyOutcome, HumanInstructions, NeedsHuman, Privilege, TestMetrics,
};
use crate::setup::receipt::{ReceiptMetadataSource, ReceiptStore};
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
fn three_todo_actions_append_complete_applied_entries_in_order_then_converge_without_mutation() {
    let fixture = JournalFixture::new("ordered-apply");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let state = Arc::new(Mutex::new(Vec::new()));
    let mut plan = vec![
        Action::test_journaled_state("test.first", 1, Privilege::None, Arc::clone(&state)).0,
        Action::test_journaled_state("test.second", 2, Privilege::Root, Arc::clone(&state)).0,
        Action::test_journaled_state("test.third", 3, Privilege::Admin, Arc::clone(&state)).0,
    ];
    let mut metadata = ReceiptMetadataSource::for_test([
        (
            "019cafd0-5c00-7000-8000-000000000001",
            "2026-09-02T10:00:00Z",
        ),
        (
            "019cafd0-5c00-7000-8000-000000000002",
            "2026-09-02T10:00:01Z",
        ),
        (
            "019cafd0-5c00-7000-8000-000000000003",
            "2026-09-02T10:00:02Z",
        ),
    ]);

    let report = apply_plan_with_journal(&mut plan, &store, &mut metadata).unwrap();

    assert_eq!(report.applied_count(), 3);
    assert!(!report.is_nothing_to_do());
    assert_eq!(*state.lock().unwrap(), vec![1, 2, 3]);
    let first_bytes = fs::read(fixture.receipt_path()).unwrap();
    let value = serde_json::from_slice::<serde_json::Value>(&first_bytes).unwrap();
    let entries = value["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry["action"]["parameters"]["action_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["test.first", "test.second", "test.third"]
    );
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry["timestamp"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "2026-09-02T10:00:00Z",
            "2026-09-02T10:00:01Z",
            "2026-09-02T10:00:02Z"
        ]
    );
    assert!(entries.iter().all(|entry| {
        entry["status"] == "applied"
            && entry["files_created"].as_array().unwrap().len() == 1
            && entry["files_modified"].as_array().unwrap().len() == 1
            && entry["services"].as_array().unwrap().len() == 1
            && entry["accounts"].as_array().unwrap().len() == 1
            && entry["registry_keys"].as_array().unwrap().len() == 1
            && entry["firewall_rules"].as_array().unwrap().len() == 1
            && entry["download_provenance"].is_object()
    }));

    let mut second_metadata = ReceiptMetadataSource::for_test([]);
    let second = apply_plan_with_journal(&mut plan, &store, &mut second_metadata).unwrap();
    assert!(second.is_nothing_to_do());
    assert_eq!(second.message(), "nothing to do");
    assert_eq!(fs::read(fixture.receipt_path()).unwrap(), first_bytes);
}

#[test]
fn failure_stops_before_unattempted_action_and_rerun_appends_only_new_successes() {
    let fixture = JournalFixture::new("failure-resume");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let state = Arc::new(Mutex::new(Vec::new()));
    let (first, _) =
        Action::test_journaled_state("test.first", 1, Privilege::None, Arc::clone(&state));
    let (failing, failing_metrics) =
        Action::test_journaled_failure("test.second", 2, Privilege::Root, Arc::clone(&state));
    let (third, third_metrics) =
        Action::test_journaled_state("test.third", 3, Privilege::Admin, Arc::clone(&state));
    let mut plan = vec![first, failing, third];
    let mut metadata = ReceiptMetadataSource::for_test([
        (
            "019cafd0-5c00-7000-8000-000000000001",
            "2026-09-02T10:00:00Z",
        ),
        (
            "019cafd0-5c00-7000-8000-000000000002",
            "2026-09-02T10:00:01Z",
        ),
    ]);

    let error = apply_plan_with_journal(&mut plan, &store, &mut metadata).unwrap_err();

    assert_eq!(error.error_code(), "setup.apply_failed");
    assert_eq!(error.exit_code(), 13);
    assert_eq!(*state.lock().unwrap(), vec![1]);
    assert_eq!(failing_metrics.mutation_calls(), 1);
    assert_eq!(third_metrics.check_calls(), 0);
    assert_eq!(third_metrics.mutation_calls(), 0);
    let first_run = store.read_snapshot().unwrap().to_json().unwrap();
    let first_value = serde_json::from_slice::<serde_json::Value>(&first_run).unwrap();
    assert_eq!(first_value["entries"].as_array().unwrap().len(), 1);

    let mut retry = vec![
        Action::test_journaled_state("test.first", 1, Privilege::None, Arc::clone(&state)).0,
        Action::test_journaled_state("test.second", 2, Privilege::Root, Arc::clone(&state)).0,
        Action::test_journaled_state("test.third", 3, Privilege::Admin, Arc::clone(&state)).0,
    ];
    let mut retry_metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000003",
        "2026-09-02T10:00:02Z",
    )]);

    let report = apply_plan_with_journal(&mut retry, &store, &mut retry_metadata).unwrap();

    assert_eq!(report.applied_count(), 2);
    assert_eq!(*state.lock().unwrap(), vec![1, 2, 3]);
    let final_value = serde_json::from_slice::<serde_json::Value>(
        &store.read_snapshot().unwrap().to_json().unwrap(),
    )
    .unwrap();
    assert_eq!(
        final_value["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["action"]["parameters"]["action_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["test.first", "test.second", "test.third"]
    );
}

#[test]
fn receipt_publication_failure_stops_after_mutation_and_rerun_recovers_ownership_forward() {
    let fixture = JournalFixture::new("publication-recovery");
    let failing_store = ReceiptStore::new_for_test_failing_before_replace(fixture.receipt_path());
    let state = Arc::new(Mutex::new(Vec::new()));
    let (first, first_metrics) =
        Action::test_journaled_state("test.first", 1, Privilege::Root, Arc::clone(&state));
    let (second, second_metrics) =
        Action::test_journaled_state("test.second", 2, Privilege::Root, Arc::clone(&state));
    let mut plan = vec![first, second];
    let mut metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000001",
        "2026-09-02T10:00:00Z",
    )]);

    let error = apply_plan_with_journal(&mut plan, &failing_store, &mut metadata).unwrap_err();

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code(), 13);
    assert_eq!(*state.lock().unwrap(), vec![1]);
    assert_eq!(first_metrics.mutation_calls(), 1);
    assert_eq!(second_metrics.check_calls(), 0);
    assert_eq!(second_metrics.mutation_calls(), 0);
    let transaction = fs::read(fixture.only_transaction_path()).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&transaction).unwrap()["phase"],
        "succeeded"
    );

    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    assert!(store.read_snapshot().unwrap().is_empty());
    let mut retry = vec![
        Action::test_journaled_state("test.first", 1, Privilege::Root, Arc::clone(&state)).0,
        Action::test_journaled_state("test.second", 2, Privilege::Root, Arc::clone(&state)).0,
    ];
    let mut retry_metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000002",
        "2026-09-02T10:00:01Z",
    )]);

    let report = apply_plan_with_journal(&mut retry, &store, &mut retry_metadata).unwrap();

    assert_eq!(report.applied_count(), 1);
    assert_eq!(report.recovered_count(), 1);
    assert_eq!(*state.lock().unwrap(), vec![1, 2]);
    let value = serde_json::from_slice::<serde_json::Value>(
        &store.read_snapshot().unwrap().to_json().unwrap(),
    )
    .unwrap();
    assert_eq!(
        value["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["action"]["parameters"]["action_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["test.first", "test.second"]
    );
    assert!(fs::read_dir(fixture.receipt_path().parent().unwrap())
        .unwrap()
        .all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("transaction")));
}

#[test]
fn crash_after_durable_prepare_before_mutation_retries_under_the_same_intent() {
    let fixture = JournalFixture::new("prepared-recovery");
    let failing_store = ReceiptStore::new_for_test_failing_after_prepare(fixture.receipt_path());
    let state = Arc::new(Mutex::new(Vec::new()));
    let (action, metrics) =
        Action::test_journaled_state("test.first", 1, Privilege::Root, Arc::clone(&state));
    let mut plan = vec![action];
    let mut metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000001",
        "2026-09-02T10:00:00Z",
    )]);

    let error = apply_plan_with_journal(&mut plan, &failing_store, &mut metadata).unwrap_err();

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(metrics.mutation_calls(), 0);
    assert!(state.lock().unwrap().is_empty());
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    assert!(store.read_snapshot().unwrap().is_empty());

    let mut retry =
        vec![Action::test_journaled_state("test.first", 1, Privilege::Root, Arc::clone(&state)).0];
    let mut no_new_metadata = ReceiptMetadataSource::for_test([]);
    let report = apply_plan_with_journal(&mut retry, &store, &mut no_new_metadata).unwrap();

    assert_eq!(report.applied_count(), 1);
    assert_eq!(*state.lock().unwrap(), vec![1]);
    let value = serde_json::from_slice::<serde_json::Value>(
        &store.read_snapshot().unwrap().to_json().unwrap(),
    )
    .unwrap();
    assert_eq!(
        value["entries"][0]["entry_id"],
        "019cafd0-5c00-7000-8000-000000000001"
    );
}

#[test]
fn prepared_intent_that_became_done_externally_refuses_receipt_ownership() {
    let fixture = JournalFixture::new("prepared-external-done");
    let interrupted_store =
        ReceiptStore::new_for_test_failing_after_prepare(fixture.receipt_path());
    let state = Arc::new(Mutex::new(Vec::new()));
    let mut interrupted =
        vec![Action::test_journaled_state("test.first", 1, Privilege::Root, Arc::clone(&state)).0];
    let mut metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000001",
        "2026-09-02T10:00:00Z",
    )]);
    apply_plan_with_journal(&mut interrupted, &interrupted_store, &mut metadata).unwrap_err();
    state.lock().unwrap().push(1);
    let before_intent = fs::read(fixture.only_transaction_path()).unwrap();
    let (retry, metrics) =
        Action::test_journaled_state("test.first", 1, Privilege::Root, Arc::clone(&state));
    let mut plan = vec![retry];
    let mut no_metadata = ReceiptMetadataSource::for_test([]);

    let error = apply_plan_with_journal(
        &mut plan,
        &ReceiptStore::new_for_test(fixture.receipt_path()),
        &mut no_metadata,
    )
    .unwrap_err();

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code(), 13);
    assert_eq!(metrics.mutation_calls(), 0);
    assert_eq!(
        fs::read(fixture.only_transaction_path()).unwrap(),
        before_intent
    );
    assert!(ReceiptStore::new_for_test(fixture.receipt_path())
        .read_snapshot()
        .unwrap()
        .is_empty());
}

#[test]
fn recovery_without_new_mutation_is_reported_as_receipt_recovery() {
    let fixture = JournalFixture::new("recovery-only-report");
    let failing_store = ReceiptStore::new_for_test_failing_before_replace(fixture.receipt_path());
    let state = Arc::new(Mutex::new(Vec::new()));
    let mut interrupted =
        vec![Action::test_journaled_state("test.first", 1, Privilege::Root, Arc::clone(&state)).0];
    let mut metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000001",
        "2026-09-02T10:00:00Z",
    )]);
    apply_plan_with_journal(&mut interrupted, &failing_store, &mut metadata).unwrap_err();

    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let (recovery, metrics) =
        Action::test_journaled_state("test.first", 1, Privilege::Root, Arc::clone(&state));
    let mut plan = vec![recovery];
    let mut no_new_metadata = ReceiptMetadataSource::for_test([]);

    let report = apply_plan_with_journal(&mut plan, &store, &mut no_new_metadata).unwrap();

    assert_eq!(report.applied_count(), 0);
    assert_eq!(report.recovered_count(), 1);
    assert!(!report.is_nothing_to_do());
    assert_eq!(report.message(), "receipt recovered");
    assert_eq!(metrics.mutation_calls(), 0);
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 1);
}

#[test]
fn succeeded_intent_recovers_after_its_action_leaves_the_current_plan() {
    let fixture = JournalFixture::new("succeeded-removed-plan");
    let failing_store = ReceiptStore::new_for_test_failing_before_replace(fixture.receipt_path());
    let state = Arc::new(Mutex::new(Vec::new()));
    let mut interrupted = vec![
        Action::test_journaled_state("test.removed", 1, Privilege::Root, Arc::clone(&state)).0,
    ];
    let mut metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000001",
        "2026-09-02T10:00:00Z",
    )]);
    apply_plan_with_journal(&mut interrupted, &failing_store, &mut metadata).unwrap_err();
    assert_eq!(*state.lock().unwrap(), vec![1]);

    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let mut empty_plan = Vec::new();
    let mut no_metadata = ReceiptMetadataSource::for_test([]);
    let report = apply_plan_with_journal(&mut empty_plan, &store, &mut no_metadata).unwrap();

    assert_eq!(report.applied_count(), 0);
    assert_eq!(report.recovered_count(), 1);
    assert_eq!(report.message(), "receipt recovered");
    let receipt = serde_json::from_slice::<serde_json::Value>(
        &store.read_snapshot().unwrap().to_json().unwrap(),
    )
    .unwrap();
    assert_eq!(
        receipt["entries"][0]["action"]["parameters"]["action_id"],
        "test.removed"
    );
    assert!(fs::read_dir(fixture.receipt_path().parent().unwrap())
        .unwrap()
        .all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("transaction")));
}

#[test]
fn succeeded_intent_recovers_stored_dynamic_before_hash_without_recomputation() {
    let fixture = JournalFixture::new("succeeded-dynamic-before-hash");
    let target = fixture.receipt_path().parent().unwrap().join("dynamic.txt");
    fs::write(&target, b"before-state\n").unwrap();
    let failing_store = ReceiptStore::new_for_test_failing_before_replace(fixture.receipt_path());
    let (action, initial_metrics) =
        Action::test_dynamic_file_modification("test.dynamic-file", target.clone());
    let mut interrupted = vec![action];
    let mut metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000001",
        "2026-09-02T10:00:00Z",
    )]);

    apply_plan_with_journal(&mut interrupted, &failing_store, &mut metadata).unwrap_err();

    assert_eq!(initial_metrics.prepare_calls(), 1);
    assert_eq!(initial_metrics.mutation_calls(), 1);
    assert_eq!(fs::read(&target).unwrap(), b"after-state\n");
    let (retry, retry_metrics) =
        Action::test_dynamic_file_modification("test.dynamic-file", target.clone());
    let mut plan = vec![retry];
    let mut no_metadata = ReceiptMetadataSource::for_test([]);

    let report = apply_plan_with_journal(
        &mut plan,
        &ReceiptStore::new_for_test(fixture.receipt_path()),
        &mut no_metadata,
    )
    .unwrap();

    assert_eq!(report.recovered_count(), 1);
    assert_eq!(report.applied_count(), 0);
    assert_eq!(retry_metrics.prepare_calls(), 0);
    assert_eq!(retry_metrics.mutation_calls(), 0);
    let receipt = serde_json::from_slice::<serde_json::Value>(
        &ReceiptStore::new_for_test(fixture.receipt_path())
            .read_snapshot()
            .unwrap()
            .to_json()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        receipt["entries"][0]["files_modified"][0]["before_sha256"],
        "b40af702b6375903b1e09c6c851d1828ac225b5356aef2c1c60e308efaf89944"
    );
    assert_eq!(
        receipt["entries"][0]["files_modified"][0]["path"],
        target.to_string_lossy().as_ref()
    );
}

#[test]
fn all_needs_human_plan_preserves_safe_pending_instructions_without_receipt_or_noop() {
    let fixture = JournalFixture::new("needs-human-report");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let state = Arc::new(Mutex::new(Vec::new()));
    let first = NeedsHuman::new(
        HumanInstructions::new("Enable Remote Login, then rerun setup.").unwrap(),
        None,
    );
    let second = NeedsHuman::new(
        HumanInstructions::new("Sign in to the package provider, then rerun setup.").unwrap(),
        None,
    );
    let (first_action, first_metrics) = Action::test_named_needs_human(
        "test.remote-login",
        Privilege::None,
        Arc::clone(&state),
        first.clone(),
    );
    let (second_action, second_metrics) = Action::test_named_needs_human(
        "test.package-login",
        Privilege::None,
        Arc::clone(&state),
        second.clone(),
    );
    let mut plan = vec![first_action, second_action];
    let mut metadata = ReceiptMetadataSource::for_test([]);

    let report = apply_plan_with_journal(&mut plan, &store, &mut metadata).unwrap();

    assert_eq!(report.applied_count(), 0);
    assert_eq!(report.recovered_count(), 0);
    assert_eq!(report.noop_count(), 0);
    assert_eq!(report.pending_count(), 2);
    assert_eq!(report.pending(), &[first, second]);
    assert!(!report.is_nothing_to_do());
    assert_eq!(report.message(), "setup actions need human attention");
    assert_eq!(first_metrics.mutation_calls(), 0);
    assert_eq!(second_metrics.mutation_calls(), 0);
    assert!(state.lock().unwrap().is_empty());
    assert!(!fixture.receipt_path().exists());
}

#[cfg(unix)]
#[test]
fn user_scope_rejects_privileged_actions_before_private_state_or_mutation() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = JournalFixture::new("user-privilege-refusal");
    fs::set_permissions(
        fixture.receipt_path().parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let store = ReceiptStore::new_user_for_test(fixture.receipt_path());
    let state = Arc::new(Mutex::new(Vec::new()));
    let (action, metrics) =
        Action::test_journaled_state("test.root", 1, Privilege::Root, Arc::clone(&state));
    let mut plan = vec![action];
    let mut metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000001",
        "2026-09-02T10:00:00Z",
    )]);

    let error = apply_plan_with_journal(&mut plan, &store, &mut metadata).unwrap_err();

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code(), 13);
    assert_eq!(metrics.check_calls(), 0);
    assert_eq!(metrics.mutation_calls(), 0);
    assert!(state.lock().unwrap().is_empty());
    assert!(!fixture.receipt_path().exists());
    assert!(fs::read_dir(fixture.receipt_path().parent().unwrap())
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn ordinary_current_user_scope_can_recover_its_restricted_journal_without_privilege() {
    let fixture = JournalFixture::new("user-scope-recovery");
    crate::platform::harden_manifest_directory(
        &fixture.root,
        crate::platform::ManifestOwner::User,
        "",
    )
    .unwrap();
    crate::platform::harden_manifest_directory(
        fixture.receipt_path().parent().unwrap(),
        crate::platform::ManifestOwner::User,
        "",
    )
    .unwrap();
    let failing_store =
        ReceiptStore::new_user_for_test_failing_before_replace(fixture.receipt_path());
    let state = Arc::new(Mutex::new(Vec::new()));
    let mut interrupted = vec![
        Action::test_journaled_state("test.user-action", 1, Privilege::None, Arc::clone(&state)).0,
    ];
    let mut metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000001",
        "2026-09-02T10:00:00Z",
    )]);
    apply_plan_with_journal(&mut interrupted, &failing_store, &mut metadata).unwrap_err();

    let mut empty_plan = Vec::new();
    let mut no_metadata = ReceiptMetadataSource::for_test([]);
    let store = ReceiptStore::new_user_for_test(fixture.receipt_path());
    let report = apply_plan_with_journal(&mut empty_plan, &store, &mut no_metadata).unwrap();

    assert_eq!(report.recovered_count(), 1);
    assert_eq!(*state.lock().unwrap(), vec![1]);
    assert_eq!(
        store.read_snapshot().unwrap().installation_scope(),
        crate::setup::receipt::InstallationScope::User
    );
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 1);
}

#[test]
fn mixed_plan_reports_applied_recovered_noop_and_pending_outcomes_independently() {
    let fixture = JournalFixture::new("mixed-report");
    let interrupted_store =
        ReceiptStore::new_for_test_failing_before_replace(fixture.receipt_path());
    let state = Arc::new(Mutex::new(Vec::new()));
    let mut interrupted = vec![
        Action::test_journaled_state("test.recovered", 1, Privilege::None, Arc::clone(&state)).0,
    ];
    let mut interrupted_metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000001",
        "2026-09-02T10:00:00Z",
    )]);
    apply_plan_with_journal(
        &mut interrupted,
        &interrupted_store,
        &mut interrupted_metadata,
    )
    .unwrap_err();

    let pending = NeedsHuman::new(
        HumanInstructions::new("Complete the one remaining local step.").unwrap(),
        None,
    );
    let (applied, applied_metrics) =
        Action::test_journaled_state("test.applied", 2, Privilege::None, Arc::clone(&state));
    let (noop, noop_metrics) =
        Action::test_journaled_state("test.noop", 1, Privilege::None, Arc::clone(&state));
    let (needs_human, pending_metrics) = Action::test_named_needs_human(
        "test.pending",
        Privilege::None,
        Arc::clone(&state),
        pending.clone(),
    );
    let mut plan = vec![applied, noop, needs_human];
    let mut metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000002",
        "2026-09-02T10:00:01Z",
    )]);

    let report = apply_plan_with_journal(
        &mut plan,
        &ReceiptStore::new_for_test(fixture.receipt_path()),
        &mut metadata,
    )
    .unwrap();

    assert_eq!(report.applied_count(), 1);
    assert_eq!(report.recovered_count(), 1);
    assert_eq!(report.noop_count(), 1);
    assert_eq!(report.pending_count(), 1);
    assert_eq!(report.pending(), &[pending]);
    assert!(!report.is_nothing_to_do());
    assert_eq!(report.message(), "setup actions applied");
    assert_eq!(applied_metrics.mutation_calls(), 1);
    assert_eq!(noop_metrics.mutation_calls(), 0);
    assert_eq!(pending_metrics.mutation_calls(), 0);
    assert_eq!(*state.lock().unwrap(), vec![1, 2]);
    assert_eq!(
        ReceiptStore::new_for_test(fixture.receipt_path())
            .read_snapshot()
            .unwrap()
            .entry_count(),
        2
    );
}

#[test]
fn secret_bearing_effects_fail_before_mutation_or_receipt_state_and_do_not_echo() {
    let secret = "api_key=super-secret-value";
    let mut service_effect = ActionEffect::test_fixture(1);
    service_effect.services = vec![secret.to_owned()];
    let mut path_effect = ActionEffect::test_fixture(1);
    #[cfg(not(target_os = "windows"))]
    {
        path_effect.files_created[0].path = format!("/opt/styrn/{secret}");
    }
    #[cfg(target_os = "windows")]
    {
        path_effect.files_created[0].path = format!(r"C:\ProgramData\Styrn\{secret}");
    }
    let mut provenance_effect = ActionEffect::test_fixture(1);
    provenance_effect.download_provenance.as_mut().unwrap().url =
        format!("https://downloads.example.test/tool?{secret}");

    for (sequence, effect) in [service_effect, path_effect, provenance_effect]
        .into_iter()
        .enumerate()
    {
        let fixture = JournalFixture::new(&format!("secret-effect-{sequence}"));
        let store = ReceiptStore::new_for_test(fixture.receipt_path());
        let state = Arc::new(Mutex::new(Vec::new()));
        let (action, metrics) = Action::test_journaled_with_effect(
            "test.secret",
            1,
            Privilege::Root,
            Arc::clone(&state),
            effect,
        );
        let mut plan = vec![action];
        let mut metadata = ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000001",
            "2026-09-02T10:00:00Z",
        )]);

        let error = apply_plan_with_journal(&mut plan, &store, &mut metadata).unwrap_err();

        assert_eq!(error.error_code(), "setup.receipt_conflict");
        assert_eq!(error.exit_code(), 13);
        assert!(!error.to_string().contains(secret));
        assert_eq!(metrics.mutation_calls(), 0);
        assert!(state.lock().unwrap().is_empty());
        assert!(!fixture.receipt_path().exists());
        assert!(fs::read_dir(fixture.receipt_path().parent().unwrap())
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("transaction")));
    }
}

#[test]
fn malformed_or_multiple_pending_intents_stop_before_mutation_without_repair() {
    for kind in ["malformed", "multiple"] {
        let fixture = JournalFixture::new(&format!("intent-{kind}"));
        let store = ReceiptStore::new_for_test(fixture.receipt_path());
        let first = fixture.transaction_path("019cafd0-5c00-7000-8000-000000000001");
        fs::write(&first, b"{malformed private intent").unwrap();
        make_private(&first);
        let second = fixture.transaction_path("019cafd0-5c00-7000-8000-000000000002");
        if kind == "multiple" {
            fs::write(&second, b"{second malformed private intent").unwrap();
            make_private(&second);
        }
        let before_first = fs::read(&first).unwrap();
        let before_second = fs::read(&second).ok();
        let state = Arc::new(Mutex::new(Vec::new()));
        let (action, metrics) =
            Action::test_journaled_state("test.first", 1, Privilege::Root, Arc::clone(&state));
        let mut plan = vec![action];
        let mut metadata = ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000003",
            "2026-09-02T10:00:02Z",
        )]);

        let error = apply_plan_with_journal(&mut plan, &store, &mut metadata).unwrap_err();

        assert_eq!(error.error_code(), "setup.receipt_conflict");
        assert_eq!(error.exit_code(), 13);
        assert_eq!(metrics.check_calls(), 0);
        assert_eq!(metrics.mutation_calls(), 0);
        assert!(state.lock().unwrap().is_empty());
        assert!(!fixture.receipt_path().exists());
        assert_eq!(fs::read(first).unwrap(), before_first);
        assert_eq!(fs::read(second).ok(), before_second);
    }
}

#[test]
fn renamed_or_insecure_pending_intents_are_not_silently_trusted_or_repaired() {
    for kind in ["renamed", "insecure"] {
        let fixture = JournalFixture::new(&format!("intent-{kind}"));
        let interrupted_store =
            ReceiptStore::new_for_test_failing_after_prepare(fixture.receipt_path());
        let state = Arc::new(Mutex::new(Vec::new()));
        let mut interrupted = vec![
            Action::test_journaled_state("test.first", 1, Privilege::Root, Arc::clone(&state)).0,
        ];
        let mut metadata = ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000001",
            "2026-09-02T10:00:00Z",
        )]);
        apply_plan_with_journal(&mut interrupted, &interrupted_store, &mut metadata).unwrap_err();
        let original = fixture.only_transaction_path();
        let path = if kind == "renamed" {
            let renamed = fixture.transaction_path("019cafd0-5c00-7000-8000-000000000002");
            fs::rename(&original, &renamed).unwrap();
            renamed
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&original, fs::Permissions::from_mode(0o644)).unwrap();
            }
            original
        };
        let before = fs::read(&path).unwrap();
        let (retry, metrics) =
            Action::test_journaled_state("test.first", 1, Privilege::Root, Arc::clone(&state));
        let mut plan = vec![retry];
        let mut no_metadata = ReceiptMetadataSource::for_test([]);

        let error = apply_plan_with_journal(
            &mut plan,
            &ReceiptStore::new_for_test(fixture.receipt_path()),
            &mut no_metadata,
        )
        .unwrap_err();

        assert_eq!(error.error_code(), "setup.receipt_conflict");
        assert_eq!(metrics.check_calls(), 0);
        assert_eq!(metrics.mutation_calls(), 0);
        assert!(state.lock().unwrap().is_empty());
        assert!(!fixture.receipt_path().exists());
        assert_eq!(fs::read(&path).unwrap(), before);
        #[cfg(unix)]
        if kind == "insecure" {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn private_intent_open_rejects_post_enumeration_symlink_fifo_and_inode_substitution() {
    for kind in ["symlink", "fifo", "inode"] {
        let fixture = JournalFixture::new(&format!("intent-open-race-{kind}"));
        let interrupted_store =
            ReceiptStore::new_for_test_failing_after_prepare(fixture.receipt_path());
        let state = Arc::new(Mutex::new(Vec::new()));
        let mut interrupted = vec![
            Action::test_journaled_state("test.first", 1, Privilege::None, Arc::clone(&state)).0,
        ];
        let mut metadata = ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000001",
            "2026-09-02T10:00:00Z",
        )]);
        apply_plan_with_journal(&mut interrupted, &interrupted_store, &mut metadata).unwrap_err();
        let intent = fixture.only_transaction_path();
        let before = fs::read(&intent).unwrap();
        let outside = fixture
            .receipt_path()
            .parent()
            .unwrap()
            .join("outside.json");
        fs::write(&outside, &before).unwrap();
        make_private(&outside);
        let store = match kind {
            "symlink" => ReceiptStore::new_for_test_swapping_intent_with_symlink(
                fixture.receipt_path(),
                outside.clone(),
            ),
            "fifo" => ReceiptStore::new_for_test_swapping_intent_with_fifo(fixture.receipt_path()),
            "inode" => ReceiptStore::new_for_test_swapping_intent_inode(fixture.receipt_path()),
            _ => unreachable!(),
        };
        let (retry, metrics) =
            Action::test_journaled_state("test.first", 1, Privilege::None, Arc::clone(&state));
        let mut plan = vec![retry];
        let mut no_metadata = ReceiptMetadataSource::for_test([]);

        let error = apply_plan_with_journal(&mut plan, &store, &mut no_metadata).unwrap_err();

        assert_eq!(error.error_code(), "setup.receipt_conflict", "{kind}");
        assert_eq!(error.exit_code(), 13, "{kind}");
        assert_eq!(metrics.check_calls(), 0, "{kind}");
        assert_eq!(metrics.mutation_calls(), 0, "{kind}");
        assert!(state.lock().unwrap().is_empty(), "{kind}");
        assert!(!fixture.receipt_path().exists(), "{kind}");
        assert_eq!(fs::read(&outside).unwrap(), before, "{kind}");
    }
}

#[cfg(windows)]
#[test]
fn private_intent_open_rejects_post_enumeration_reparse_and_inode_substitution() {
    for kind in ["reparse", "inode"] {
        let fixture = JournalFixture::new(&format!("intent-open-race-{kind}"));
        let interrupted_store =
            ReceiptStore::new_for_test_failing_after_prepare(fixture.receipt_path());
        let state = Arc::new(Mutex::new(Vec::new()));
        let mut interrupted = vec![
            Action::test_journaled_state("test.first", 1, Privilege::None, Arc::clone(&state)).0,
        ];
        let mut metadata = ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000001",
            "2026-09-02T10:00:00Z",
        )]);
        apply_plan_with_journal(&mut interrupted, &interrupted_store, &mut metadata).unwrap_err();
        let intent = fixture.only_transaction_path();
        let before = fs::read(&intent).unwrap();
        let outside = fixture
            .receipt_path()
            .parent()
            .unwrap()
            .join("outside.json");
        fs::write(&outside, &before).unwrap();
        let store = if kind == "reparse" {
            ReceiptStore::new_for_test_swapping_intent_with_reparse(
                fixture.receipt_path(),
                outside.clone(),
            )
        } else {
            ReceiptStore::new_for_test_swapping_intent_inode(fixture.receipt_path())
        };
        let (retry, metrics) =
            Action::test_journaled_state("test.first", 1, Privilege::None, Arc::clone(&state));
        let mut plan = vec![retry];
        let mut no_metadata = ReceiptMetadataSource::for_test([]);

        let error = apply_plan_with_journal(&mut plan, &store, &mut no_metadata).unwrap_err();

        assert_eq!(error.error_code(), "setup.receipt_conflict", "{kind}");
        assert_eq!(metrics.check_calls(), 0, "{kind}");
        assert_eq!(metrics.mutation_calls(), 0, "{kind}");
        assert!(!fixture.receipt_path().exists(), "{kind}");
        assert_eq!(fs::read(&outside).unwrap(), before, "{kind}");
        if kind == "reparse" {
            assert!(fs::symlink_metadata(&intent)
                .unwrap()
                .file_type()
                .is_symlink());
        } else {
            assert!(fs::symlink_metadata(&intent).unwrap().file_type().is_file());
        }
    }
}

#[test]
fn recovered_intent_must_match_the_exact_action_effect_and_recovery_state() {
    for kind in ["missing-action", "effect-mismatch", "needs-human"] {
        let fixture = JournalFixture::new(&format!("intent-conflict-{kind}"));
        let interrupted_store =
            ReceiptStore::new_for_test_failing_after_prepare(fixture.receipt_path());
        let state = Arc::new(Mutex::new(Vec::new()));
        let mut interrupted = vec![
            Action::test_journaled_state("test.first", 1, Privilege::Root, Arc::clone(&state)).0,
        ];
        let mut metadata = ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000001",
            "2026-09-02T10:00:00Z",
        )]);
        apply_plan_with_journal(&mut interrupted, &interrupted_store, &mut metadata).unwrap_err();
        let (action, metrics) = match kind {
            "missing-action" => {
                Action::test_journaled_state("test.other", 1, Privilege::Root, Arc::clone(&state))
            }
            "effect-mismatch" => {
                Action::test_journaled_state("test.first", 2, Privilege::Root, Arc::clone(&state))
            }
            "needs-human" => Action::test_needs_human(
                Privilege::Root,
                Arc::clone(&state),
                NeedsHuman::new(
                    HumanInstructions::new("Complete local setup.").unwrap(),
                    None,
                ),
            ),
            _ => unreachable!(),
        };
        let mut plan = vec![action];
        let mut no_metadata = ReceiptMetadataSource::for_test([]);

        let error = apply_plan_with_journal(
            &mut plan,
            &ReceiptStore::new_for_test(fixture.receipt_path()),
            &mut no_metadata,
        )
        .unwrap_err();

        assert_eq!(error.error_code(), "setup.receipt_conflict");
        assert_eq!(metrics.mutation_calls(), 0);
        assert!(state.lock().unwrap().is_empty());
        assert!(!fixture.receipt_path().exists());
        assert!(fixture.only_transaction_path().exists());
    }
}

#[test]
fn concurrent_apply_sessions_mutate_and_journal_one_action_exactly_once() {
    let fixture = JournalFixture::new("concurrent-apply");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let state = Arc::new(Mutex::new(Vec::new()));
    let barrier = Arc::new(std::sync::Barrier::new(2));

    let reports = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for sequence in 1..=2 {
            let store = store.clone();
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            handles.push(scope.spawn(move || {
                let mut plan =
                    vec![Action::test_journaled_state("test.first", 1, Privilege::Root, state).0];
                let id = format!("019cafd0-5c00-7000-8000-{sequence:012}");
                let mut metadata =
                    ReceiptMetadataSource::for_test([(id.as_str(), "2026-09-02T10:00:00Z")]);
                barrier.wait();
                apply_plan_with_journal(&mut plan, &store, &mut metadata).unwrap()
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });

    assert_eq!(*state.lock().unwrap(), vec![1]);
    assert_eq!(
        reports
            .iter()
            .map(|report| report.applied_count())
            .sum::<usize>(),
        1
    );
    assert_eq!(
        reports
            .iter()
            .filter(|report| report.is_nothing_to_do())
            .count(),
        1
    );
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 1);
}

#[test]
fn duplicate_action_names_are_rejected_before_checks_intents_or_mutation() {
    let fixture = JournalFixture::new("duplicate-action-names");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let state = Arc::new(Mutex::new(Vec::new()));
    let (first, first_metrics) =
        Action::test_journaled_state("test.duplicate", 1, Privilege::Root, Arc::clone(&state));
    let (second, second_metrics) =
        Action::test_journaled_state("test.duplicate", 2, Privilege::Root, Arc::clone(&state));
    let mut plan = vec![first, second];
    let mut metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000001",
        "2026-09-02T10:00:00Z",
    )]);

    let error = apply_plan_with_journal(&mut plan, &store, &mut metadata).unwrap_err();

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code(), 13);
    assert_eq!(first_metrics.check_calls(), 0);
    assert_eq!(second_metrics.check_calls(), 0);
    assert_eq!(first_metrics.mutation_calls(), 0);
    assert_eq!(second_metrics.mutation_calls(), 0);
    assert!(state.lock().unwrap().is_empty());
    assert!(!fixture.receipt_path().exists());
    assert!(fs::read_dir(fixture.receipt_path().parent().unwrap())
        .unwrap()
        .all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("transaction")));
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
    let state = Arc::new(Mutex::new(Vec::new()));
    let (mut action, metrics) = state_driven(Arc::clone(&state));

    assert_eq!(
        action.apply().unwrap(),
        ApplyOutcome::Applied(ActionEffect::test_fixture(1))
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
    let effect = ActionEffect::test_fixture(1);

    assert!(matches!(
        action.revert(&effect),
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
fn plan_code_cannot_invoke_the_action_apply_route() {
    assert_fixture_fails_with_cfg(
        "real_plan_apply.rs",
        &["plan_action_apply_fixture"],
        FixtureExpectation::new(
            "E0624",
            "method `apply` is private",
            2,
            Some("private method"),
            "hostile_apply.rs",
        ),
    );
}

#[test]
fn plan_code_cannot_invoke_apply_with_receipt_journaling() {
    assert_fixture_fails(
        "plan_journal_apply.rs",
        FixtureExpectation::new(
            "E0603",
            "function import `apply_plan_with_journal` is private",
            13,
            Some("private function import"),
            "plan_journal_apply.rs",
        ),
    );
}

#[test]
fn callers_cannot_construct_forged_finalized_action_effects() {
    assert_fixture_fails(
        "forged_action_effect.rs",
        FixtureExpectation::new(
            "E0451",
            "fields `files_created`, `files_modified`, `services`, `accounts`, `registry_keys`, `firewall_rules` and `download_provenance` of struct `action::ActionEffect` are private",
            10,
            Some("private field"),
            "forged_action_effect.rs",
        ),
    );
}

#[test]
fn callers_cannot_construct_forged_receipt_entries() {
    assert_fixture_fails_with_cfg(
        "forged_receipt_entry.rs",
        &["plan_receipt_forge_fixture"],
        FixtureExpectation::new(
            "E0624",
            "associated function `from_json` is private",
            2,
            Some("private associated function"),
            "hostile_receipt.rs",
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
    let full_journal_fixture = matches!(
        name,
        "plan_journal_apply.rs" | "forged_action_effect.rs" | "forged_receipt_entry.rs"
    );
    if !full_journal_fixture {
        command.arg("--cfg").arg("action_core_fixture");
    }
    if configurations.contains(&"test") {
        command.arg("--test");
    }
    for configuration in configurations {
        command.arg("--cfg").arg(configuration);
    }
    for dependency in [
        "base64",
        "chrono",
        "libc",
        "serde",
        "serde_json",
        "thiserror",
        "uuid",
    ] {
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
            if ![
                "base64",
                "chrono",
                "libc",
                "serde",
                "serde_json",
                "thiserror",
                "uuid",
            ]
            .contains(&name)
            {
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
        for dependency in [
            "base64",
            "chrono",
            "libc",
            "serde",
            "serde_json",
            "thiserror",
            "uuid",
        ] {
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

struct JournalFixture {
    root: PathBuf,
    receipt: PathBuf,
}

impl JournalFixture {
    fn new(label: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "styrn-action-journal-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        let directory = root.join("styrn");
        fs::create_dir_all(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let receipt = directory.join("receipt.json");
        Self { root, receipt }
    }

    fn receipt_path(&self) -> &Path {
        &self.receipt
    }

    fn transaction_path(&self, id: &str) -> PathBuf {
        self.receipt
            .parent()
            .unwrap()
            .join(format!(".receipt.json.transaction.{id}.json"))
    }

    fn only_transaction_path(&self) -> PathBuf {
        let paths = fs::read_dir(self.receipt.parent().unwrap())
            .unwrap()
            .filter_map(|entry| {
                let path = entry.unwrap().path();
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .contains("transaction")
                    .then_some(path)
            })
            .collect::<Vec<_>>();
        assert_eq!(paths.len(), 1);
        paths.into_iter().next().unwrap()
    }
}

fn make_private(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(windows)]
    let _ = path;
}

impl Drop for JournalFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
