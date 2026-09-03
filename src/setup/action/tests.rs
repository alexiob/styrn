use super::{
    apply_plan_with_journal,
    execution::{
        apply_plan_with_runner, ApplyPlanError, DurableReceiptBinding, PreparedActionRunner,
    },
    Action, ActionDescription, ActionEffect, ActionError, ActionName, ApplyOutcome,
    HumanInstructions, MutationCompletion, NeedsHuman, PendingSeverity, Privilege, ScriptFragment,
    TestMetrics, VerifiedActionEffect, WorkerDirectoryNode,
};
use crate::setup::receipt::{ReceiptMetadataSource, ReceiptStore, ReceiptStoreError};
use chrono::{TimeZone, Utc};
use sha2::{Digest as _, Sha256};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Barrier, Mutex,
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

fn worker_directory_action(
    root: &Path,
    node: WorkerDirectoryNode,
    path: &Path,
    state: Arc<Mutex<Vec<u8>>>,
) -> (Action, TestMetrics) {
    Action::test_worker_directory(
        crate::setup::receipt::InstallationScope::User,
        crate::platform::resolve_current_worker_principal().unwrap(),
        root.to_path_buf(),
        node,
        path.to_path_buf(),
        state,
    )
}

fn harden_user_journal_fixture(fixture: &JournalFixture) {
    let principal = crate::platform::resolve_current_worker_principal().unwrap();
    crate::platform::harden_manifest_directory(
        &fixture.root,
        crate::platform::ManifestOwner::User,
        &principal,
    )
    .unwrap();
    crate::platform::harden_manifest_directory(
        fixture.receipt_path().parent().unwrap(),
        crate::platform::ManifestOwner::User,
        &principal,
    )
    .unwrap();
}

fn native_user_worker_root() -> PathBuf {
    let principal = crate::platform::resolve_current_worker_principal().unwrap();
    crate::platform::resolve_worker_directory_layout(
        crate::setup::receipt::InstallationScope::User,
        &principal,
        None,
    )
    .unwrap()
    .root()
    .to_path_buf()
}

const LEGACY_PENDING_PUBLICATION_RECEIPT: &str = r#"{
  "schema_version": 1,
  "installation_scope": "system",
  "entries": [
    {
      "entry_id": "019cafd0-5c00-7000-8000-000000000121",
      "action": {
        "type": "foundation",
        "parameters": {
          "action_id": "test.legacy-publication"
        }
      },
      "timestamp": "2026-09-02T10:21:00Z",
      "privilege_used": "none",
      "files_created": [],
      "files_modified": [],
      "services": [],
      "accounts": [],
      "registry_keys": [],
      "firewall_rules": [],
      "download_provenance": null,
      "status": "pending"
    }
  ]
}
"#;

#[test]
fn verified_effect_is_bound_before_native_authority_release() {
    let state = Arc::new(Mutex::new(Vec::new()));
    let (mut action, metrics) = state_driven(Arc::clone(&state));
    let prepared = action.prepare().unwrap();
    let mut callback_calls = 0;

    let (completion, value) = action
        .execute_prepared_and_bind(|verified| {
            callback_calls += 1;
            assert_eq!(verified.effect(), prepared.effect());
            Ok::<_, ()>("durable receipt binding")
        })
        .unwrap();

    assert_eq!(completion, MutationCompletion::Applied);
    assert_eq!(value, "durable receipt binding");
    assert_eq!(callback_calls, 1);
    assert_eq!(metrics.mutation_calls(), 1);
    assert_eq!(*state.lock().unwrap(), vec![1]);
}

#[test]
fn prepared_runner_rejects_effect_drift_before_the_succeeded_transition() {
    struct DriftRunner;

    impl PreparedActionRunner for DriftRunner {
        fn execute_prepared_and_bind<Bind>(
            &mut self,
            action: &mut Action,
            _expected: &ActionEffect,
            bind: Bind,
        ) -> Result<(MutationCompletion, DurableReceiptBinding), ApplyPlanError>
        where
            Bind: for<'authority> FnOnce(
                VerifiedActionEffect<'authority>,
            )
                -> Result<DurableReceiptBinding, ReceiptStoreError>,
        {
            action
                .execute_prepared_and_bind(|_| {
                    let drifted = ActionEffect::test_fixture(99);
                    bind(VerifiedActionEffect {
                        effect: &drifted,
                        _authority: std::marker::PhantomData,
                    })
                })
                .map_err(|error| match error {
                    super::PreparedExecutionError::Action(error) => ApplyPlanError::Action(error),
                    super::PreparedExecutionError::ReceiptConflict => {
                        ApplyPlanError::Receipt(ReceiptStoreError::IntentConflict)
                    }
                    super::PreparedExecutionError::Binding(error) => ApplyPlanError::Receipt(error),
                })
        }
    }

    let fixture = JournalFixture::new("prepared-runner-effect-drift");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let state = Arc::new(Mutex::new(Vec::new()));
    let mut plan = vec![state_driven(Arc::clone(&state)).0];

    let error = apply_plan_with_runner(
        &mut plan,
        &store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000001",
            "2026-09-02T10:00:00Z",
        )]),
        &mut DriftRunner,
    )
    .unwrap_err();

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code(), 13);
    assert_eq!(*state.lock().unwrap(), vec![1]);
    assert!(store.read_snapshot().unwrap().is_empty());
    let intent = fs::read(fixture.only_transaction_path()).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&intent).unwrap()["phase"],
        "prepared"
    );
}

#[test]
fn prepared_runner_orders_durable_binding_before_native_authority_release() {
    struct NativeTraceRunner<'a> {
        fixture: &'a JournalFixture,
        layout: crate::platform::WorkerDirectoryLayout,
        trace: Arc<Mutex<Vec<&'static str>>>,
    }

    impl PreparedActionRunner for NativeTraceRunner<'_> {
        fn execute_prepared_and_bind<Bind>(
            &mut self,
            _action: &mut Action,
            expected: &ActionEffect,
            bind: Bind,
        ) -> Result<(MutationCompletion, DurableReceiptBinding), ApplyPlanError>
        where
            Bind: for<'authority> FnOnce(
                VerifiedActionEffect<'authority>,
            )
                -> Result<DurableReceiptBinding, ReceiptStoreError>,
        {
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(
                    &fs::read(self.fixture.only_transaction_path()).unwrap()
                )
                .unwrap()["phase"],
                "prepared"
            );
            self.trace.lock().unwrap().push("prepared-durable");
            let authority = crate::platform::TestNativeMutationAuthority::for_test();
            let crate::platform::WorkerDirectoryNodeCreateOutcome::Created(creation) =
                crate::platform::create_worker_directory_node(
                    &self.layout,
                    WorkerDirectoryNode::Root,
                    &authority,
                )
                .unwrap()
            else {
                panic!("fresh trace root was not created")
            };
            self.trace.lock().unwrap().push("native-created");
            let trace = Arc::clone(&self.trace);
            let fixture = self.fixture;
            let bound = creation
                .bind_after_reverify(|_| {
                    trace.lock().unwrap().push("native-reverified");
                    trace.lock().unwrap().push("effect-equal");
                    let result = bind(VerifiedActionEffect {
                        effect: expected,
                        _authority: std::marker::PhantomData,
                    });
                    let intent: serde_json::Value =
                        serde_json::from_slice(&fs::read(fixture.only_transaction_path()).unwrap())
                            .unwrap();
                    assert_eq!(intent["phase"], "succeeded");
                    trace.lock().unwrap().push("intent-succeeded-durable");
                    assert_eq!(
                        ReceiptStore::new_for_test(fixture.receipt_path())
                            .read_snapshot()
                            .unwrap()
                            .entry_count(),
                        1
                    );
                    trace.lock().unwrap().push("receipt-appended-durable");
                    result
                })
                .map_err(|error| match error {
                    crate::platform::WorkerDirectoryBindingError::Reverification(_) => {
                        ApplyPlanError::Action(ActionError::apply_failed(
                            ActionName::parse("test.trace").unwrap(),
                        ))
                    }
                    crate::platform::WorkerDirectoryBindingError::Binding(error) => {
                        ApplyPlanError::Receipt(error)
                    }
                    crate::platform::WorkerDirectoryBindingError::AuthorityRetirement(_) => {
                        ApplyPlanError::Action(ActionError::apply_failed(
                            ActionName::parse("test.trace").unwrap(),
                        ))
                    }
                })?;
            match bound {
                crate::platform::WorkerDirectoryBound::Bound(binding) => {
                    self.trace.lock().unwrap().push("native-evidence-retired");
                    Ok((MutationCompletion::Applied, binding))
                }
                crate::platform::WorkerDirectoryBound::BoundWithRetirementFailure { .. } => {
                    Err(ActionError::apply_failed(ActionName::parse("test.trace").unwrap()).into())
                }
            }
        }
    }

    let fixture = JournalFixture::new("prepared-runner-native-order");
    let principal = crate::platform::resolve_current_worker_principal().unwrap();
    let layout = crate::platform::resolve_worker_directory_layout(
        crate::platform::InstallationScope::System,
        &principal,
        Some(&fixture.root.join("worker-root")),
    )
    .unwrap();
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut runner = NativeTraceRunner {
        fixture: &fixture,
        layout,
        trace: Arc::clone(&trace),
    };
    let state = Arc::new(Mutex::new(Vec::new()));
    let mut plan = vec![Action::test_journaled_state("test.trace", 1, Privilege::None, state).0];
    let mut metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000001",
        "2026-09-02T10:00:00Z",
    )]);

    apply_plan_with_runner(
        &mut plan,
        &ReceiptStore::new_for_test(fixture.receipt_path()),
        &mut metadata,
        &mut runner,
    )
    .unwrap();
    assert!(fixture.only_transaction_path_if_present().is_none());
    trace.lock().unwrap().push("intent-retired");

    assert_eq!(
        trace.lock().unwrap().as_slice(),
        [
            "prepared-durable",
            "native-created",
            "native-reverified",
            "effect-equal",
            "intent-succeeded-durable",
            "receipt-appended-durable",
            "native-evidence-retired",
            "intent-retired",
        ]
    );
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
            && entry["directories_created"] == serde_json::json!([])
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
fn receipt_retirement_failure_retains_appended_receipt_and_succeeded_intent_for_recovery() {
    let fixture = JournalFixture::new("intent-retirement-failure");
    let failing_store =
        ReceiptStore::new_for_test_failing_before_intent_retirement(fixture.receipt_path());
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
    assert_eq!(error.exit_code(), 13);
    assert_eq!(metrics.mutation_calls(), 1);
    assert_eq!(*state.lock().unwrap(), vec![1]);
    assert_eq!(failing_store.read_snapshot().unwrap().entry_count(), 1);
    let intent_path = fixture.only_transaction_path();
    let intent = fs::read(&intent_path).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&intent).unwrap()["phase"],
        "succeeded"
    );

    let mut empty_plan = Vec::new();
    let recovery = apply_plan_with_journal(
        &mut empty_plan,
        &ReceiptStore::new_for_test(fixture.receipt_path()),
        &mut ReceiptMetadataSource::for_test([]),
    )
    .unwrap();

    assert_eq!(recovery.recovered_count(), 1);
    assert_eq!(
        ReceiptStore::new_for_test(fixture.receipt_path())
            .read_snapshot()
            .unwrap()
            .entry_count(),
        1
    );
    assert!(!intent_path.exists());
}

#[test]
fn applied_then_failed_is_receipted_before_the_typed_action_error_stops_the_plan() {
    struct AppliedThenFailedRunner;

    impl PreparedActionRunner for AppliedThenFailedRunner {
        fn execute_prepared_and_bind<Bind>(
            &mut self,
            action: &mut Action,
            _expected: &ActionEffect,
            bind: Bind,
        ) -> Result<(MutationCompletion, DurableReceiptBinding), ApplyPlanError>
        where
            Bind: for<'authority> FnOnce(
                VerifiedActionEffect<'authority>,
            )
                -> Result<DurableReceiptBinding, ReceiptStoreError>,
        {
            let (_, binding) =
                action
                    .execute_prepared_and_bind(bind)
                    .map_err(|error| match error {
                        super::PreparedExecutionError::Action(error) => {
                            ApplyPlanError::Action(error)
                        }
                        super::PreparedExecutionError::ReceiptConflict => {
                            ApplyPlanError::Receipt(ReceiptStoreError::IntentConflict)
                        }
                        super::PreparedExecutionError::Binding(error) => {
                            ApplyPlanError::Receipt(error)
                        }
                    })?;
            Ok((
                MutationCompletion::AppliedThenFailed(ActionError::apply_failed(
                    action.name().clone(),
                )),
                binding,
            ))
        }
    }

    let fixture = JournalFixture::new("applied-then-failed");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
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

    let error = apply_plan_with_runner(
        &mut plan,
        &store,
        &mut metadata,
        &mut AppliedThenFailedRunner,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        ApplyPlanError::Action(ActionError::ApplyFailed { .. })
    ));
    assert_eq!(error.error_code(), "setup.apply_failed");
    assert_eq!(error.exit_code(), 13);
    assert_eq!(*state.lock().unwrap(), vec![1]);
    assert_eq!(first_metrics.mutation_calls(), 1);
    assert_eq!(second_metrics.check_calls(), 0);
    assert_eq!(second_metrics.mutation_calls(), 0);
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 1);
    assert!(fixture.only_transaction_path_if_present().is_none());
}

#[cfg(unix)]
#[test]
fn native_retirement_failure_preserves_the_appended_binding_and_succeeded_intent() {
    use std::os::unix::fs::PermissionsExt;

    struct RetirementFailureRunner<'a> {
        fixture: &'a JournalFixture,
        layout: crate::platform::WorkerDirectoryLayout,
        marker: Option<PathBuf>,
        saved_marker: Option<PathBuf>,
    }

    impl PreparedActionRunner for RetirementFailureRunner<'_> {
        fn execute_prepared_and_bind<Bind>(
            &mut self,
            action: &mut Action,
            expected: &ActionEffect,
            bind: Bind,
        ) -> Result<(MutationCompletion, DurableReceiptBinding), ApplyPlanError>
        where
            Bind: for<'authority> FnOnce(
                VerifiedActionEffect<'authority>,
            )
                -> Result<DurableReceiptBinding, ReceiptStoreError>,
        {
            let authority = crate::platform::TestNativeMutationAuthority::for_test();
            let crate::platform::WorkerDirectoryNodeCreateOutcome::Created(creation) =
                crate::platform::create_worker_directory_node(
                    &self.layout,
                    WorkerDirectoryNode::Support { ordinal: 0 },
                    &authority,
                )
                .unwrap()
            else {
                panic!("fresh synthetic support node was not created")
            };
            let marker = fs::read_dir(&self.fixture.root)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".styrn-worker-provenance-")
                })
                .expect("native creation retained one provenance marker");
            let saved_marker = self.fixture.root.join("saved-retirement-evidence");
            let bound = creation
                .bind_after_reverify(|_| {
                    let binding = bind(VerifiedActionEffect {
                        effect: expected,
                        _authority: std::marker::PhantomData,
                    })?;
                    assert!(matches!(binding, DurableReceiptBinding::Appended));
                    fs::rename(&marker, &saved_marker).unwrap();
                    fs::create_dir(&marker).unwrap();
                    fs::set_permissions(&marker, fs::Permissions::from_mode(0o700)).unwrap();
                    Ok::<_, ReceiptStoreError>(binding)
                })
                .map_err(|error| match error {
                    crate::platform::WorkerDirectoryBindingError::Reverification(_) => {
                        ApplyPlanError::Action(ActionError::apply_failed(action.name().clone()))
                    }
                    crate::platform::WorkerDirectoryBindingError::Binding(error) => {
                        ApplyPlanError::Receipt(error)
                    }
                    crate::platform::WorkerDirectoryBindingError::AuthorityRetirement(_) => {
                        ApplyPlanError::Action(ActionError::apply_failed(action.name().clone()))
                    }
                })?;
            match bound {
                crate::platform::WorkerDirectoryBound::BoundWithRetirementFailure {
                    value,
                    error,
                } => {
                    assert!(matches!(value, DurableReceiptBinding::Appended));
                    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
                    self.marker = Some(marker);
                    self.saved_marker = Some(saved_marker);
                    Err(ActionError::apply_failed(action.name().clone()).into())
                }
                crate::platform::WorkerDirectoryBound::Bound(_) => {
                    panic!("altered native evidence unexpectedly retired")
                }
            }
        }
    }

    let fixture = JournalFixture::new("native-retirement-binding");
    harden_user_journal_fixture(&fixture);
    let principal = crate::platform::resolve_current_worker_principal().unwrap();
    let root = fixture.root.join("worker-support").join("worker-root");
    let layout = crate::platform::worker_directory_layout_for_test(
        crate::platform::InstallationScope::User,
        principal,
        root.clone(),
        Some(fixture.root.clone()),
    );
    let node = WorkerDirectoryNode::Support { ordinal: 0 };
    let path = layout.path_for_node(node).unwrap();
    let store =
        ReceiptStore::new_user_for_test_with_worker_layout(fixture.receipt_path(), layout.clone());
    let mut runner = RetirementFailureRunner {
        fixture: &fixture,
        layout: layout.clone(),
        marker: None,
        saved_marker: None,
    };
    let mut plan =
        vec![worker_directory_action(&root, node, &path, Arc::new(Mutex::new(Vec::new()))).0];

    let error = apply_plan_with_runner(
        &mut plan,
        &store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000001",
            "2026-09-02T10:00:00Z",
        )]),
        &mut runner,
    )
    .unwrap_err();

    assert_eq!(error.error_code(), "setup.apply_failed");
    assert_eq!(error.exit_code(), 13);
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 1);
    let intent_path = fixture.only_transaction_path();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(&intent_path).unwrap()).unwrap()
            ["phase"],
        "succeeded"
    );
    let marker = runner.marker.take().unwrap();
    let saved_marker = runner.saved_marker.take().unwrap();
    fs::remove_dir(&marker).unwrap();
    fs::rename(saved_marker, marker).unwrap();

    let recovery =
        apply_plan_with_journal(&mut [], &store, &mut ReceiptMetadataSource::for_test([])).unwrap();
    assert_eq!(recovery.recovered_count(), 1);
    assert!(!intent_path.exists());
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
fn worker_directory_receipt_recovery_succeeded_is_plan_independent() {
    assert_worker_directory_succeeded_recovery_retires_exact_native_evidence(
        "worker-directory-succeeded-plan-independent",
    );
}

#[test]
fn worker_directory_succeeded_recovery_retires_exact_native_evidence() {
    assert_worker_directory_succeeded_recovery_retires_exact_native_evidence(
        "worker-directory-succeeded-native-retirement",
    );
}

fn assert_worker_directory_succeeded_recovery_retires_exact_native_evidence(label: &str) {
    let fixture = JournalFixture::new(label);
    harden_user_journal_fixture(&fixture);
    let principal = crate::platform::resolve_current_worker_principal().unwrap();
    let root = fixture.root.join("worker-support").join("worker-root");
    let layout = crate::platform::worker_directory_layout_for_test(
        crate::platform::InstallationScope::User,
        principal,
        root.clone(),
        Some(fixture.root.clone()),
    );
    let node = WorkerDirectoryNode::Support { ordinal: 0 };
    let path = layout.path_for_node(node).unwrap();
    let authority = crate::platform::TestNativeMutationAuthority::for_test();
    let crate::platform::WorkerDirectoryNodeCreateOutcome::Created(creation) =
        crate::platform::create_worker_directory_node(&layout, node, &authority).unwrap()
    else {
        panic!("fresh synthetic support node was not created")
    };
    drop(creation);
    #[cfg(unix)]
    assert!(matches!(
        crate::platform::inspect_worker_directory_node(&layout, node),
        crate::platform::WorkerDirectoryNodeInspection::Conflict(_)
    ));
    let state = Arc::new(Mutex::new(Vec::new()));
    let (action, metrics) = worker_directory_action(&root, node, &path, Arc::clone(&state));
    let mut interrupted = vec![action];
    let mut metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000001",
        "2026-09-02T10:00:00Z",
    )]);

    let error = apply_plan_with_journal(
        &mut interrupted,
        &ReceiptStore::new_user_for_test_with_worker_layout_failing_before_replace(
            fixture.receipt_path(),
            layout.clone(),
        ),
        &mut metadata,
    )
    .unwrap_err();

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(metrics.mutation_calls(), 1);
    assert_eq!(*state.lock().unwrap(), vec![1]);
    let intent_before = fs::read(fixture.only_transaction_path()).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&intent_before).unwrap()["phase"],
        "succeeded"
    );

    let mut empty_plan = Vec::new();
    let mut no_metadata = ReceiptMetadataSource::for_test([]);
    let store =
        ReceiptStore::new_user_for_test_with_worker_layout(fixture.receipt_path(), layout.clone());
    let report = apply_plan_with_journal(&mut empty_plan, &store, &mut no_metadata).unwrap();

    assert_eq!(report.recovered_count(), 1);
    assert_eq!(report.applied_count(), 0);
    let receipt = serde_json::from_slice::<serde_json::Value>(
        &store.read_snapshot().unwrap().to_json().unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["entries"][0]["action"]["type"], "worker_directory");
    assert_eq!(
        receipt["entries"][0]["action"]["parameters"]["action_id"],
        "identity.directory.support-0"
    );
    assert_eq!(
        receipt["entries"][0]["action"]["parameters"]["node"],
        serde_json::json!({ "type": "support", "ordinal": 0 })
    );
    assert_eq!(
        receipt["entries"][0]["directories_created"],
        serde_json::json!([{ "path": path.to_string_lossy() }])
    );
    assert!(fs::read_dir(fixture.receipt_path().parent().unwrap())
        .unwrap()
        .all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("transaction")));
    assert_eq!(
        crate::platform::inspect_worker_directory_node(&layout, node),
        crate::platform::WorkerDirectoryNodeInspection::Healthy
    );
}

#[cfg(unix)]
#[test]
fn worker_directory_succeeded_recovery_rejects_altered_native_evidence_without_deleting_it() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture = JournalFixture::new("worker-directory-succeeded-altered-evidence");
    harden_user_journal_fixture(&fixture);
    let principal = crate::platform::resolve_current_worker_principal().unwrap();
    let root = fixture.root.join("worker-support").join("worker-root");
    let layout = crate::platform::worker_directory_layout_for_test(
        crate::platform::InstallationScope::User,
        principal,
        root.clone(),
        Some(fixture.root.clone()),
    );
    let node = WorkerDirectoryNode::Support { ordinal: 0 };
    let path = layout.path_for_node(node).unwrap();
    let authority = crate::platform::TestNativeMutationAuthority::for_test();
    let crate::platform::WorkerDirectoryNodeCreateOutcome::Created(creation) =
        crate::platform::create_worker_directory_node(&layout, node, &authority).unwrap()
    else {
        panic!("fresh synthetic support node was not created")
    };
    drop(creation);
    let marker = fs::read_dir(&fixture.root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".styrn-worker-provenance-")
        })
        .expect("native creation retained one provenance marker");

    let state = Arc::new(Mutex::new(Vec::new()));
    let mut interrupted = vec![worker_directory_action(&root, node, &path, state).0];
    apply_plan_with_journal(
        &mut interrupted,
        &ReceiptStore::new_user_for_test_with_worker_layout_failing_before_replace(
            fixture.receipt_path(),
            layout.clone(),
        ),
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000001",
            "2026-09-02T10:00:00Z",
        )]),
    )
    .unwrap_err();
    let intent_path = fixture.only_transaction_path();
    let intent_before = fs::read(&intent_path).unwrap();

    let saved_marker = fixture.root.join("saved-native-provenance");
    fs::rename(&marker, &saved_marker).unwrap();
    fs::create_dir(&marker).unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o700)).unwrap();
    let replacement = fs::symlink_metadata(&marker).unwrap();
    let saved = fs::symlink_metadata(&saved_marker).unwrap();
    let store =
        ReceiptStore::new_user_for_test_with_worker_layout(fixture.receipt_path(), layout.clone());

    let error = apply_plan_with_journal(&mut [], &store, &mut ReceiptMetadataSource::for_test([]))
        .unwrap_err();

    assert_eq!(error.error_code(), "setup.apply_failed");
    assert_eq!(error.exit_code(), 13);
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 1);
    assert_eq!(fs::read(&intent_path).unwrap(), intent_before);
    let retained_replacement = fs::symlink_metadata(&marker).unwrap();
    let retained_saved = fs::symlink_metadata(&saved_marker).unwrap();
    assert_eq!(
        (retained_replacement.dev(), retained_replacement.ino()),
        (replacement.dev(), replacement.ino())
    );
    assert_eq!(
        (retained_saved.dev(), retained_saved.ino()),
        (saved.dev(), saved.ino())
    );

    fs::remove_dir(&marker).unwrap();
    fs::rename(&saved_marker, &marker).unwrap();
    let recovery =
        apply_plan_with_journal(&mut [], &store, &mut ReceiptMetadataSource::for_test([])).unwrap();
    assert_eq!(recovery.recovered_count(), 1);
    assert!(!intent_path.exists());
}

#[test]
fn worker_directory_receipt_recovery_prepared_done_or_parameter_drift_retains_evidence() {
    for kind in ["done", "parameter-drift"] {
        let fixture = JournalFixture::new(&format!("worker-directory-prepared-{kind}"));
        harden_user_journal_fixture(&fixture);
        let root = native_user_worker_root();
        let path = root.join("jobs");
        let state = Arc::new(Mutex::new(Vec::new()));
        let (action, initial_metrics) =
            worker_directory_action(&root, WorkerDirectoryNode::Jobs, &path, Arc::clone(&state));
        let mut interrupted = vec![action];
        let mut metadata = ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000001",
            "2026-09-02T10:00:00Z",
        )]);
        apply_plan_with_journal(
            &mut interrupted,
            &ReceiptStore::new_user_for_test_failing_after_prepare(fixture.receipt_path()),
            &mut metadata,
        )
        .unwrap_err();
        assert_eq!(initial_metrics.mutation_calls(), 0);
        let intent_path = fixture.only_transaction_path();
        let intent_before = fs::read(&intent_path).unwrap();

        let (retry, retry_metrics) = if kind == "done" {
            state.lock().unwrap().push(1);
            worker_directory_action(&root, WorkerDirectoryNode::Jobs, &path, Arc::clone(&state))
        } else {
            let drifted_root = fixture.root.join("other-worker-root");
            let drifted_path = drifted_root.join("jobs");
            worker_directory_action(
                &drifted_root,
                WorkerDirectoryNode::Jobs,
                &drifted_path,
                Arc::clone(&state),
            )
        };
        let mut plan = vec![retry];
        let mut no_metadata = ReceiptMetadataSource::for_test([]);

        let error = apply_plan_with_journal(
            &mut plan,
            &ReceiptStore::new_user_for_test(fixture.receipt_path()),
            &mut no_metadata,
        )
        .unwrap_err();

        assert_eq!(error.error_code(), "setup.receipt_conflict", "{kind}");
        assert_eq!(error.exit_code(), 13, "{kind}");
        assert_eq!(retry_metrics.mutation_calls(), 0, "{kind}");
        assert_eq!(fs::read(&intent_path).unwrap(), intent_before, "{kind}");
        assert!(ReceiptStore::new_user_for_test(fixture.receipt_path())
            .read_snapshot()
            .unwrap()
            .is_empty());
    }
}

#[test]
fn worker_directory_receipt_recovery_pending_keeps_typed_parameters_and_safe_descriptor() {
    let fixture = JournalFixture::new("worker-directory-pending-parameters");
    harden_user_journal_fixture(&fixture);
    let root = native_user_worker_root();
    let path = root.join("jobs");
    let state = Arc::new(Mutex::new(Vec::new()));
    let needs_human = NeedsHuman::new(
        HumanInstructions::new("Resolve the worker directory conflict, then rerun setup.").unwrap(),
        None,
    );
    let (action, metrics) = Action::test_worker_directory_needs_human(
        crate::setup::receipt::InstallationScope::User,
        crate::platform::resolve_current_worker_principal().unwrap(),
        root,
        WorkerDirectoryNode::Jobs,
        path.clone(),
        Arc::clone(&state),
        needs_human.clone(),
    );
    let mut plan = vec![action];
    let mut metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000001",
        "2026-09-02T10:00:00Z",
    )]);
    let store = ReceiptStore::new_user_for_test(fixture.receipt_path());

    let report = apply_plan_with_journal(&mut plan, &store, &mut metadata).unwrap();

    assert_eq!(report.pending_count(), 1);
    assert_eq!(report.pending()[0].id().as_str(), "identity.directory.jobs");
    assert_eq!(report.pending()[0].needs_human(), &needs_human);
    assert_eq!(metrics.mutation_calls(), 0);
    assert!(state.lock().unwrap().is_empty());
    let receipt = serde_json::from_slice::<serde_json::Value>(
        &store.read_snapshot().unwrap().to_json().unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["entries"][0]["action"]["type"], "worker_directory");
    assert_eq!(
        receipt["entries"][0]["action"]["parameters"]["path"],
        path.to_string_lossy().as_ref()
    );
    assert_eq!(
        receipt["entries"][0]["directories_created"],
        serde_json::json!([])
    );
    assert_eq!(receipt["entries"][0]["status"], "pending");
}

#[test]
fn worker_directory_receipt_recovery_pending_parameter_drift_is_a_conflict() {
    let fixture = JournalFixture::new("worker-directory-pending-drift");
    harden_user_journal_fixture(&fixture);
    let root = native_user_worker_root();
    let path = root.join("jobs");
    let state = Arc::new(Mutex::new(Vec::new()));
    let needs_human = NeedsHuman::new(
        HumanInstructions::new("Resolve the worker directory conflict, then rerun setup.").unwrap(),
        None,
    );
    let (action, _) = Action::test_worker_directory_needs_human(
        crate::setup::receipt::InstallationScope::User,
        crate::platform::resolve_current_worker_principal().unwrap(),
        root,
        WorkerDirectoryNode::Jobs,
        path,
        Arc::clone(&state),
        needs_human.clone(),
    );
    let mut plan = vec![action];
    let mut metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000001",
        "2026-09-02T10:00:00Z",
    )]);
    let store = ReceiptStore::new_user_for_test(fixture.receipt_path());
    apply_plan_with_journal(&mut plan, &store, &mut metadata).unwrap();
    let before = fs::read(fixture.receipt_path()).unwrap();

    let drifted_root = fixture.root.join("other-worker-root");
    let drifted_path = drifted_root.join("jobs");
    let (drifted, metrics) = Action::test_worker_directory_needs_human(
        crate::setup::receipt::InstallationScope::User,
        crate::platform::resolve_current_worker_principal().unwrap(),
        drifted_root,
        WorkerDirectoryNode::Jobs,
        drifted_path,
        Arc::clone(&state),
        needs_human,
    );
    let mut drifted_plan = vec![drifted];
    let mut no_metadata = ReceiptMetadataSource::for_test([]);

    let error = apply_plan_with_journal(&mut drifted_plan, &store, &mut no_metadata).unwrap_err();

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code(), 13);
    assert_eq!(metrics.mutation_calls(), 0);
    assert!(state.lock().unwrap().is_empty());
    assert_eq!(fs::read(fixture.receipt_path()).unwrap(), before);
}

#[test]
fn needs_human_journals_each_current_occurrence_once_and_recurrence_after_witnessed_resolution() {
    let fixture = JournalFixture::new("needs-human-report");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let state = Arc::new(Mutex::new(Vec::new()));
    let first = NeedsHuman::new(
        HumanInstructions::new(
            "Open System Settings > General > Sharing, enable Remote Login, then rerun setup.",
        )
        .unwrap(),
        Some(ScriptFragment::DeferredAction(
            ActionName::parse("macos.remote-login").unwrap(),
        )),
    )
    .with_severity(PendingSeverity::Info);
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

    assert_eq!(report.applied_count(), 0);
    assert_eq!(report.recovered_count(), 0);
    assert_eq!(report.noop_count(), 0);
    assert_eq!(report.pending_count(), 2);
    assert_eq!(report.pending()[0].id().as_str(), "test.remote-login");
    assert_eq!(report.pending()[0].severity(), PendingSeverity::Info);
    assert_eq!(report.pending()[0].needs_human(), &first);
    assert_eq!(
        report.pending()[0].fragment_action_id(),
        Some("macos.remote-login")
    );
    assert_eq!(report.pending()[1].id().as_str(), "test.package-login");
    assert_eq!(report.pending()[1].severity(), PendingSeverity::Warning);
    assert_eq!(report.pending()[1].needs_human(), &second);
    assert!(!report.is_nothing_to_do());
    assert_eq!(report.message(), "setup actions need human attention");
    assert_eq!(first_metrics.mutation_calls(), 0);
    assert_eq!(second_metrics.mutation_calls(), 0);

    let mut draft = crate::manifest::MachineManifest::parse_toml(include_str!(
        "../../../examples/machine.controller-worker.toml"
    ))
    .unwrap()
    .without_machine_id();
    crate::setup::pending::project_manifest_for_test(&mut draft, report.pending()).unwrap();
    let projected = draft.pending_actions.as_ref().unwrap();
    assert_eq!(projected.len(), 2);
    assert_eq!(projected[0].id, "test.remote-login");
    assert_eq!(
        projected[0].severity,
        crate::manifest::PendingSeverity::Info
    );
    assert_eq!(
        projected[0].message,
        "Open System Settings > General > Sharing, enable Remote Login, then rerun setup."
    );
    assert_eq!(projected[1].id, "test.package-login");
    assert_eq!(
        projected[1].severity,
        crate::manifest::PendingSeverity::Warning
    );
    let manifest_path = fixture.root.join("machine.toml");
    let manifest_store = crate::manifest::MachineManifestStore::new_for_test(&manifest_path);
    let machine_id = crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        report.completion(),
        &mut metadata,
    )
    .unwrap();
    let first_manifest = fs::read(&manifest_path).unwrap();

    let timestamp = Utc.with_ymd_and_hms(2026, 9, 2, 10, 0, 2).unwrap();
    let default_outcome = crate::setup::pending::PendingPolicy::default()
        .evaluate(timestamp, report.completion())
        .unwrap();
    assert_eq!(default_outcome.exit_code().as_i32(), 0);
    let default_json = serde_json::from_str::<serde_json::Value>(
        &crate::output::to_json(default_outcome.envelope()).unwrap(),
    )
    .unwrap();
    assert_eq!(default_json["ok"], true);
    assert_eq!(default_json["warnings"].as_array().unwrap().len(), 2);
    assert_eq!(default_json["data"]["pending"].as_array().unwrap().len(), 2);
    assert_eq!(
        default_json["data"]["pending"][0]["id"],
        "test.remote-login"
    );
    assert_eq!(default_json["data"]["pending"][0]["severity"], "info");

    let strict_outcome = crate::setup::pending::PendingPolicy::new(true)
        .evaluate(timestamp, report.completion())
        .unwrap();
    assert_eq!(strict_outcome.exit_code().as_i32(), 13);
    let strict_json = serde_json::from_str::<serde_json::Value>(
        &crate::output::to_json(strict_outcome.envelope()).unwrap(),
    )
    .unwrap();
    assert_eq!(strict_json["ok"], false);
    assert_eq!(strict_json["errors"][0]["code"], "setup.needs_human");
    assert!(strict_json["data"].is_null());
    assert_eq!(
        strict_json["errors"][0]["details"]["pending"],
        default_json["data"]["pending"]
    );
    let command_schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/command-v1.schema.json")).unwrap();
    let command_validator = jsonschema::validator_for(&command_schema).unwrap();
    assert!(command_validator.is_valid(&strict_json));
    assert!(strict_json.to_string().contains("test.package-login"));
    assert!(!strict_json.to_string().contains("applied"));

    let mut human = Vec::new();
    crate::setup::pending::render_human(&mut human, report.completion()).unwrap();
    let human = String::from_utf8(human).unwrap();
    assert_eq!(
        human
            .matches("Pending actions requiring your attention:")
            .count(),
        1
    );
    assert!(human.contains("[info] test.remote-login"));
    assert!(human.contains("deferred action: macos.remote-login; not rendered or executed"));
    assert!(!human.contains("sudo "));
    assert!(state.lock().unwrap().is_empty());

    let receipt = serde_json::from_slice::<serde_json::Value>(
        &store.read_snapshot().unwrap().to_json().unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["entries"].as_array().unwrap().len(), 2);
    assert_eq!(
        receipt["entries"][0]["action"]["parameters"]["action_id"],
        "test.remote-login"
    );
    assert_eq!(receipt["entries"][0]["status"], "pending");
    assert_eq!(receipt["entries"][0]["privilege_used"], "none");
    assert_eq!(
        receipt["entries"][0]["directories_created"],
        serde_json::json!([])
    );
    assert_eq!(
        receipt["entries"][0]["files_created"],
        serde_json::json!([])
    );
    assert_eq!(
        receipt["entries"][0]["files_modified"],
        serde_json::json!([])
    );
    assert_eq!(receipt["entries"][0]["services"], serde_json::json!([]));
    assert_eq!(receipt["entries"][0]["accounts"], serde_json::json!([]));
    assert_eq!(
        receipt["entries"][0]["registry_keys"],
        serde_json::json!([])
    );
    assert_eq!(
        receipt["entries"][0]["firewall_rules"],
        serde_json::json!([])
    );
    assert!(receipt["entries"][0]["download_provenance"].is_null());
    assert_eq!(
        receipt["entries"][1]["action"]["parameters"]["action_id"],
        "test.package-login"
    );

    let mut no_metadata = ReceiptMetadataSource::for_test([]);
    let rerun = apply_plan_with_journal(&mut plan, &store, &mut no_metadata).unwrap();
    assert_eq!(rerun.pending_count(), 2);
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 2);
    let rerun_machine_id = crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        rerun.completion(),
        &mut no_metadata,
    )
    .unwrap();
    assert_eq!(rerun_machine_id, machine_id);
    assert_eq!(fs::read(&manifest_path).unwrap(), first_manifest);
    let rerun_default_json = crate::output::to_json(
        crate::setup::pending::PendingPolicy::default()
            .evaluate(timestamp, rerun.completion())
            .unwrap()
            .envelope(),
    )
    .unwrap();
    assert_eq!(
        rerun_default_json,
        crate::output::to_json(default_outcome.envelope()).unwrap()
    );
    let rerun_strict_json = crate::output::to_json(
        crate::setup::pending::PendingPolicy::new(true)
            .evaluate(timestamp, rerun.completion())
            .unwrap()
            .envelope(),
    )
    .unwrap();
    assert_eq!(
        rerun_strict_json,
        crate::output::to_json(strict_outcome.envelope()).unwrap()
    );

    let receipt_before_resolution = store.read_snapshot().unwrap().to_json().unwrap();
    let (still_pending, still_pending_metrics) = Action::test_named_needs_human(
        "test.package-login",
        Privilege::None,
        Arc::clone(&state),
        second,
    );
    let mut resolved_plan = vec![still_pending];
    let mut resolution_metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000004",
        "2026-09-02T10:00:03Z",
    )]);
    let resolved =
        apply_plan_with_journal(&mut resolved_plan, &store, &mut resolution_metadata).unwrap();
    crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        resolved.completion(),
        &mut resolution_metadata,
    )
    .unwrap();
    assert_eq!(resolved.pending_count(), 1);
    assert_eq!(resolved.pending()[0].id().as_str(), "test.package-login");
    assert_eq!(still_pending_metrics.mutation_calls(), 0);
    let receipt_after_resolution = store.read_snapshot().unwrap().to_json().unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&receipt_after_resolution).unwrap()["entries"],
        serde_json::from_slice::<serde_json::Value>(&receipt_before_resolution).unwrap()["entries"]
    );
    let current = manifest_store.read().unwrap().manifest;
    let current_pending = current.pending_actions.unwrap();
    assert_eq!(current_pending.len(), 1);
    assert_eq!(current_pending[0].id, "test.package-login");

    let (recurring, recurring_metrics) = Action::test_named_needs_human(
        "test.remote-login",
        Privilege::None,
        Arc::clone(&state),
        first,
    );
    let mut recurring_plan = vec![recurring];
    let mut recurrence_metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000005",
        "2026-09-02T10:00:04Z",
    )]);
    let recurrence =
        apply_plan_with_journal(&mut recurring_plan, &store, &mut recurrence_metadata).unwrap();
    assert_eq!(recurrence.pending_count(), 1);
    assert_eq!(recurrence.pending()[0].id().as_str(), "test.remote-login");
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 3);
    let mut failed_checkpoint_metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000006",
        "2026-09-02T10:00:05Z",
    )]);
    let publication_error = crate::setup::pending::publish_manifest(
        &crate::manifest::MachineManifestStore::new_with_failing_publication_replace(
            &manifest_path,
        ),
        &store,
        &mut draft,
        recurrence.completion(),
        &mut failed_checkpoint_metadata,
    )
    .unwrap_err();
    assert_eq!(publication_error.error_code(), "setup.apply_failed");
    let mut repair_entry_metadata = ReceiptMetadataSource::for_test([]);
    let repaired_recurrence =
        apply_plan_with_journal(&mut recurring_plan, &store, &mut repair_entry_metadata).unwrap();
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 3);
    let mut recurrence_checkpoint_metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000006",
        "2026-09-02T10:00:05Z",
    )]);
    crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        repaired_recurrence.completion(),
        &mut recurrence_checkpoint_metadata,
    )
    .unwrap();
    let recurring_manifest = fs::read(&manifest_path).unwrap();
    let recurring_receipt = store.read_snapshot().unwrap().to_json().unwrap();
    let mut current_metadata = ReceiptMetadataSource::for_test([]);
    let current_recurrence =
        apply_plan_with_journal(&mut recurring_plan, &store, &mut current_metadata).unwrap();
    crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        current_recurrence.completion(),
        &mut current_metadata,
    )
    .unwrap();
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 3);
    assert_eq!(
        store.read_snapshot().unwrap().to_json().unwrap(),
        recurring_receipt
    );
    assert_eq!(fs::read(&manifest_path).unwrap(), recurring_manifest);
    assert_eq!(recurring_metrics.mutation_calls(), 0);
    assert_eq!(first_metrics.mutation_calls(), 0);
    assert_eq!(second_metrics.mutation_calls(), 0);
}

#[test]
fn unresolved_rerun_token_reuses_the_exact_current_pending_entry_id() {
    let fixture = JournalFixture::new("pending-exact-rerun-occurrence");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let state = Arc::new(Mutex::new(Vec::new()));
    let mut plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            state,
            NeedsHuman::new(
                HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
                None,
            ),
        )
        .0,
    ];
    let mut metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000111",
        "2026-09-02T10:20:00Z",
    )]);

    let first = apply_plan_with_journal(&mut plan, &store, &mut metadata).unwrap();
    let rerun =
        apply_plan_with_journal(&mut plan, &store, &mut ReceiptMetadataSource::for_test([]))
            .unwrap();

    assert!(first.completion().occurrences() == rerun.completion().occurrences());
    let receipt: serde_json::Value =
        serde_json::from_slice(&store.read_snapshot().unwrap().to_json().unwrap()).unwrap();
    assert_eq!(receipt["entries"].as_array().unwrap().len(), 1);
    assert_eq!(
        receipt["entries"][0]["entry_id"],
        "019cafd0-5c00-7000-8000-000000000111"
    );
}

#[test]
fn empty_completed_execution_can_publish_a_resolution_epoch() {
    let fixture = JournalFixture::new("pending-empty-completion-epoch");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let manifest_path = fixture.root.join("machine.toml");
    let manifest_store = crate::manifest::MachineManifestStore::new_for_test(&manifest_path);
    let mut plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            Arc::new(Mutex::new(Vec::new())),
            NeedsHuman::new(
                HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
                None,
            ),
        )
        .0,
    ];
    let pending = apply_plan_with_journal(
        &mut plan,
        &store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000112",
            "2026-09-02T10:20:01Z",
        )]),
    )
    .unwrap();
    let mut draft = pending_manifest_draft();
    crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        pending.completion(),
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000113",
            "2026-09-02T10:20:02Z",
        )]),
    )
    .unwrap();
    let receipt_before = store.read_snapshot().unwrap().to_json().unwrap();

    let cleared =
        apply_plan_with_journal(&mut [], &store, &mut ReceiptMetadataSource::for_test([])).unwrap();
    assert!(cleared.completion().occurrences().is_empty());
    crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        cleared.completion(),
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000114",
            "2026-09-02T10:20:03Z",
        )]),
    )
    .unwrap();

    let before: serde_json::Value = serde_json::from_slice(&receipt_before).unwrap();
    let after: serde_json::Value =
        serde_json::from_slice(&store.read_snapshot().unwrap().to_json().unwrap()).unwrap();
    assert_eq!(after["entries"], before["entries"]);
    assert_eq!(after["pending_publications"].as_array().unwrap().len(), 2);
    assert_eq!(
        after["pending_publications"][1]["pending"],
        serde_json::json!([])
    );
    assert!(manifest_store
        .read()
        .unwrap()
        .manifest
        .pending_actions
        .is_none());
}

#[test]
fn completion_witness_treats_a_verified_prepared_publication_as_effective() {
    let fixture = JournalFixture::new("pending-completion-effective-intent");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let manifest_path = fixture.root.join("machine.toml");
    let mut plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            Arc::new(Mutex::new(Vec::new())),
            NeedsHuman::new(
                HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
                None,
            ),
        )
        .0,
    ];
    let first = apply_plan_with_journal(
        &mut plan,
        &store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000115",
            "2026-09-02T10:20:04Z",
        )]),
    )
    .unwrap();
    let mut draft = pending_manifest_draft();
    crate::setup::pending::publish_manifest(
        &crate::manifest::MachineManifestStore::new_with_failing_publication_replace(
            &manifest_path,
        ),
        &store,
        &mut draft,
        first.completion(),
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000116",
            "2026-09-02T10:20:05Z",
        )]),
    )
    .unwrap_err();
    assert!(fixture.pending_publication_intent_path().exists());

    let rerun =
        apply_plan_with_journal(&mut plan, &store, &mut ReceiptMetadataSource::for_test([]))
            .unwrap();
    let _ = rerun.completion().receipt_witness();
    assert!(first.completion().occurrences() == rerun.completion().occurrences());
    crate::setup::pending::publish_manifest(
        &crate::manifest::MachineManifestStore::new_for_test(&manifest_path),
        &store,
        &mut draft,
        rerun.completion(),
        &mut ReceiptMetadataSource::for_test([]),
    )
    .unwrap();

    assert!(!fixture.pending_publication_intent_path().exists());
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 1);
}

#[test]
fn completed_execution_rejects_an_equivalent_action_in_a_different_receipt_store() {
    let first_fixture = JournalFixture::new("completed-cross-store-first");
    let second_fixture = JournalFixture::new("completed-cross-store-second");
    let first_store = ReceiptStore::new_for_test(first_fixture.receipt_path());
    let second_store = ReceiptStore::new_for_test(second_fixture.receipt_path());
    let needs_human = NeedsHuman::new(
        HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
        None,
    );
    let mut first_plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            Arc::new(Mutex::new(Vec::new())),
            needs_human.clone(),
        )
        .0,
    ];
    let mut second_plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            Arc::new(Mutex::new(Vec::new())),
            needs_human,
        )
        .0,
    ];
    let first = apply_plan_with_journal(
        &mut first_plan,
        &first_store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000121",
            "2026-09-02T10:21:00Z",
        )]),
    )
    .unwrap();
    let second = apply_plan_with_journal(
        &mut second_plan,
        &second_store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000122",
            "2026-09-02T10:21:01Z",
        )]),
    )
    .unwrap();
    let manifest_path = second_fixture.root.join("machine.toml");
    let manifest_store = crate::manifest::MachineManifestStore::new_for_test(&manifest_path);
    let mut draft = pending_manifest_draft();
    let receipt_before = fs::read(second_fixture.receipt_path()).unwrap();
    let mut publication_metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000123",
        "2026-09-02T10:21:02Z",
    )]);

    let error = crate::setup::pending::publish_manifest(
        &manifest_store,
        &second_store,
        &mut draft,
        first.completion(),
        &mut publication_metadata,
    )
    .unwrap_err();

    assert!(
        matches!(
            &error,
            crate::setup::pending::PendingError::Receipt(ReceiptStoreError::IntentConflict)
        ),
        "{error:?}"
    );
    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code().as_i32(), 13);
    assert!(draft.pending_actions.is_none());
    assert_eq!(
        fs::read(second_fixture.receipt_path()).unwrap(),
        receipt_before
    );
    assert!(!manifest_path.exists());

    crate::setup::pending::publish_manifest(
        &manifest_store,
        &second_store,
        &mut draft,
        second.completion(),
        &mut publication_metadata,
    )
    .unwrap();
    let receipt: serde_json::Value =
        serde_json::from_slice(&second_store.read_snapshot().unwrap().to_json().unwrap()).unwrap();
    assert_eq!(
        receipt["pending_publications"][0]["publication_id"],
        "019cafd0-5c00-7000-8000-000000000123"
    );
}

#[test]
fn completed_execution_rejects_cross_scope_and_principal_bindings() {
    let fixture = JournalFixture::new("completed-cross-scope");
    crate::platform::harden_manifest_directory(
        &fixture.root,
        crate::platform::ManifestOwner::User,
        &crate::platform::resolve_current_worker_principal().unwrap(),
    )
    .unwrap();
    crate::platform::harden_manifest_directory(
        fixture.receipt_path().parent().unwrap(),
        crate::platform::ManifestOwner::User,
        &crate::platform::resolve_current_worker_principal().unwrap(),
    )
    .unwrap();
    let store = ReceiptStore::new_user_for_test(fixture.receipt_path());
    let mut plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            Arc::new(Mutex::new(Vec::new())),
            NeedsHuman::new(
                HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
                None,
            ),
        )
        .0,
    ];
    let report = apply_plan_with_journal(
        &mut plan,
        &store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000124",
            "2026-09-02T10:21:03Z",
        )]),
    )
    .unwrap();
    let manifest_path = fixture.root.join("machine.toml");
    let manifest_store = crate::manifest::MachineManifestStore::new_for_test(&manifest_path);
    let mut draft = pending_manifest_draft();
    let receipt_before = fs::read(fixture.receipt_path()).unwrap();

    let error = crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        report.completion(),
        &mut ReceiptMetadataSource::for_test([]),
    )
    .unwrap_err();

    assert!(matches!(
        &error,
        crate::setup::pending::PendingError::Receipt(ReceiptStoreError::IntentConflict)
    ));
    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code().as_i32(), 13);
    assert!(draft.pending_actions.is_none());
    assert_eq!(fs::read(fixture.receipt_path()).unwrap(), receipt_before);
    assert!(!manifest_path.exists());
}

#[test]
fn stale_completed_execution_cannot_publish_after_a_resolved_then_recurring_occurrence() {
    let fixture = JournalFixture::new("completed-stale-recurrence");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let manifest_path = fixture.root.join("machine.toml");
    let manifest_store = crate::manifest::MachineManifestStore::new_for_test(&manifest_path);
    let needs_human = NeedsHuman::new(
        HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
        None,
    );
    let mut initial_plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            Arc::new(Mutex::new(Vec::new())),
            needs_human.clone(),
        )
        .0,
    ];
    let initial = apply_plan_with_journal(
        &mut initial_plan,
        &store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000125",
            "2026-09-02T10:21:04Z",
        )]),
    )
    .unwrap();
    let mut draft = pending_manifest_draft();
    crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        initial.completion(),
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000126",
            "2026-09-02T10:21:05Z",
        )]),
    )
    .unwrap();
    let cleared =
        apply_plan_with_journal(&mut [], &store, &mut ReceiptMetadataSource::for_test([])).unwrap();
    crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        cleared.completion(),
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000127",
            "2026-09-02T10:21:06Z",
        )]),
    )
    .unwrap();
    let mut recurrence_plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            Arc::new(Mutex::new(Vec::new())),
            needs_human,
        )
        .0,
    ];
    let recurrence = apply_plan_with_journal(
        &mut recurrence_plan,
        &store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000128",
            "2026-09-02T10:21:07Z",
        )]),
    )
    .unwrap();
    let receipt_before = fs::read(fixture.receipt_path()).unwrap();
    let manifest_before = fs::read(&manifest_path).unwrap();
    let mut publication_metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000129",
        "2026-09-02T10:21:08Z",
    )]);

    let error = crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        initial.completion(),
        &mut publication_metadata,
    )
    .unwrap_err();

    assert!(matches!(
        &error,
        crate::setup::pending::PendingError::Receipt(ReceiptStoreError::IntentConflict)
    ));
    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code().as_i32(), 13);
    assert!(draft.pending_actions.is_none());
    assert_eq!(fs::read(fixture.receipt_path()).unwrap(), receipt_before);
    assert_eq!(fs::read(&manifest_path).unwrap(), manifest_before);

    crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        recurrence.completion(),
        &mut publication_metadata,
    )
    .unwrap();
    let receipt: serde_json::Value =
        serde_json::from_slice(&store.read_snapshot().unwrap().to_json().unwrap()).unwrap();
    assert_eq!(
        receipt["pending_publications"][2]["publication_id"],
        "019cafd0-5c00-7000-8000-000000000129"
    );
    assert_eq!(
        receipt["pending_publications"][2]["pending"][0]["entry_id"],
        "019cafd0-5c00-7000-8000-000000000128"
    );
}

#[test]
fn completed_execution_rejects_a_missing_durable_occurrence() {
    let fixture = JournalFixture::new("completed-missing-occurrence");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let mut plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            Arc::new(Mutex::new(Vec::new())),
            NeedsHuman::new(
                HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
                None,
            ),
        )
        .0,
    ];
    let report = apply_plan_with_journal(
        &mut plan,
        &store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000130",
            "2026-09-02T10:21:09Z",
        )]),
    )
    .unwrap();
    let original_receipt = fs::read(fixture.receipt_path()).unwrap();
    let empty_fixture = JournalFixture::new("completed-empty-replacement");
    let empty = ReceiptStore::new_for_test(empty_fixture.receipt_path())
        .read_snapshot()
        .unwrap()
        .to_json()
        .unwrap();
    fs::write(fixture.receipt_path(), &empty).unwrap();
    let manifest_path = fixture.root.join("machine.toml");
    let manifest_store = crate::manifest::MachineManifestStore::new_for_test(&manifest_path);
    let mut draft = pending_manifest_draft();
    let mut publication_metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000131",
        "2026-09-02T10:21:10Z",
    )]);

    let error = crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        report.completion(),
        &mut publication_metadata,
    )
    .unwrap_err();

    assert!(
        matches!(
            &error,
            crate::setup::pending::PendingError::Receipt(ReceiptStoreError::IntentConflict)
        ),
        "{error:?}"
    );
    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code().as_i32(), 13);
    assert!(draft.pending_actions.is_none());
    assert_eq!(fs::read(fixture.receipt_path()).unwrap(), empty);
    assert!(!manifest_path.exists());

    fs::write(fixture.receipt_path(), original_receipt).unwrap();
    crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        report.completion(),
        &mut publication_metadata,
    )
    .unwrap();
    let receipt: serde_json::Value =
        serde_json::from_slice(&store.read_snapshot().unwrap().to_json().unwrap()).unwrap();
    assert_eq!(
        receipt["pending_publications"][0]["publication_id"],
        "019cafd0-5c00-7000-8000-000000000131"
    );
}

#[test]
fn pending_receipt_failure_stops_before_manifest_or_mutation() {
    let fixture = JournalFixture::new("pending-receipt-failure");
    let receipt_store = ReceiptStore::new_for_test_failing_before_replace(fixture.receipt_path());
    let manifest_path = fixture.root.join("machine.toml");
    let state = Arc::new(Mutex::new(Vec::new()));
    let needs_human = NeedsHuman::new(
        HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
        None,
    );
    let (action, metrics) = Action::test_named_needs_human(
        "test.local-approval",
        Privilege::None,
        Arc::clone(&state),
        needs_human,
    );
    let mut plan = vec![action];
    let mut metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000011",
        "2026-09-02T10:01:00Z",
    )]);

    let error = apply_plan_with_journal(&mut plan, &receipt_store, &mut metadata).unwrap_err();

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code(), 13);
    assert_eq!(metrics.mutation_calls(), 0);
    assert!(state.lock().unwrap().is_empty());
    assert!(receipt_store.read_snapshot().unwrap().is_empty());
    assert!(!manifest_path.exists());
}

#[test]
fn failed_manifest_publication_repairs_on_rerun_without_duplicate_pending_history() {
    let fixture = JournalFixture::new("pending-manifest-recovery");
    let receipt_store = ReceiptStore::new_for_test(fixture.receipt_path());
    let manifest_path = fixture.root.join("machine.toml");
    let state = Arc::new(Mutex::new(Vec::new()));
    let needs_human = NeedsHuman::new(
        HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
        None,
    );
    let (action, metrics) = Action::test_named_needs_human(
        "test.local-approval",
        Privilege::None,
        Arc::clone(&state),
        needs_human,
    );
    let mut plan = vec![action];
    let mut metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000012",
        "2026-09-02T10:02:00Z",
    )]);
    let report = apply_plan_with_journal(&mut plan, &receipt_store, &mut metadata).unwrap();
    let receipt_before = receipt_store.read_snapshot().unwrap().to_json().unwrap();
    let mut draft = pending_manifest_draft();

    let error = crate::setup::pending::publish_manifest(
        &crate::manifest::MachineManifestStore::new_with_failing_publication_replace(
            &manifest_path,
        ),
        &receipt_store,
        &mut draft,
        report.completion(),
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000014",
            "2026-09-02T10:02:01Z",
        )]),
    )
    .unwrap_err();

    assert_eq!(error.error_code(), "setup.apply_failed");
    assert_eq!(error.exit_code().as_i32(), 13);
    assert!(draft.pending_actions.is_none());
    assert!(!manifest_path.exists());
    assert!(fixture.pending_publication_intent_path().exists());
    assert_eq!(metrics.mutation_calls(), 0);

    let mut no_metadata = ReceiptMetadataSource::for_test([]);
    let rerun = apply_plan_with_journal(&mut plan, &receipt_store, &mut no_metadata).unwrap();
    let mut repair_metadata = ReceiptMetadataSource::for_test([]);
    crate::setup::pending::publish_manifest(
        &crate::manifest::MachineManifestStore::new_for_test(&manifest_path),
        &receipt_store,
        &mut draft,
        rerun.completion(),
        &mut repair_metadata,
    )
    .unwrap();
    assert!(!fixture.pending_publication_intent_path().exists());
    let repaired_receipt = receipt_store.read_snapshot().unwrap().to_json().unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&repaired_receipt).unwrap()["entries"],
        serde_json::from_slice::<serde_json::Value>(&receipt_before).unwrap()["entries"]
    );
    assert_eq!(
        crate::manifest::MachineManifestStore::new_for_test(&manifest_path)
            .read()
            .unwrap()
            .manifest
            .pending_actions
            .unwrap()[0]
            .id,
        "test.local-approval"
    );
}

#[test]
fn legacy_v1_pending_publication_prefix_recovers_and_checkpoints_current_receipt() {
    let fixture = JournalFixture::new("legacy-v1-pending-publication-recovery");
    let receipt_store = ReceiptStore::new_for_test(fixture.receipt_path());
    let manifest_path = fixture.root.join("machine.toml");
    let state = Arc::new(Mutex::new(Vec::new()));
    let mut plan = vec![
        Action::test_named_needs_human(
            "test.legacy-publication",
            Privilege::None,
            Arc::clone(&state),
            NeedsHuman::new(
                HumanInstructions::new("Complete the legacy approval, then rerun setup.").unwrap(),
                None,
            ),
        )
        .0,
    ];
    let report = apply_plan_with_journal(
        &mut plan,
        &receipt_store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000121",
            "2026-09-02T10:21:00Z",
        )]),
    )
    .unwrap();
    let mut draft = pending_manifest_draft();
    crate::setup::pending::publish_manifest(
        &crate::manifest::MachineManifestStore::new_with_failing_publication_replace(
            &manifest_path,
        ),
        &receipt_store,
        &mut draft,
        report.completion(),
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000122",
            "2026-09-02T10:21:01Z",
        )]),
    )
    .unwrap_err();

    fs::write(
        fixture.receipt_path(),
        LEGACY_PENDING_PUBLICATION_RECEIPT.as_bytes(),
    )
    .unwrap();
    let intent_path = fixture.pending_publication_intent_path();
    let mut intent: serde_json::Value =
        serde_json::from_slice(&fs::read(&intent_path).unwrap()).unwrap();
    let legacy_digest = Sha256::digest(LEGACY_PENDING_PUBLICATION_RECEIPT.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    intent["receipt_prefix_sha256"] = serde_json::json!(legacy_digest);
    let mut intent_bytes = serde_json::to_vec_pretty(&intent).unwrap();
    intent_bytes.push(b'\n');
    fs::write(&intent_path, &intent_bytes).unwrap();

    let different_path = |name: &str| fixture.root.join(name).to_string_lossy().into_owned();
    let mut tampered = Vec::new();
    let mut wrong_scope = intent.clone();
    wrong_scope["installation_scope"] = serde_json::json!("user");
    tampered.push((
        "scope",
        LEGACY_PENDING_PUBLICATION_RECEIPT.as_bytes().to_vec(),
        wrong_scope,
    ));
    let mut wrong_principal = intent.clone();
    wrong_principal["worker_principal"]["name"] = serde_json::json!("other-worker");
    tampered.push((
        "principal",
        LEGACY_PENDING_PUBLICATION_RECEIPT.as_bytes().to_vec(),
        wrong_principal,
    ));
    let mut wrong_receipt_path = intent.clone();
    wrong_receipt_path["receipt_path"] = serde_json::json!(different_path("other-receipt.json"));
    tampered.push((
        "receipt path",
        LEGACY_PENDING_PUBLICATION_RECEIPT.as_bytes().to_vec(),
        wrong_receipt_path,
    ));
    let mut wrong_count = intent.clone();
    wrong_count["receipt_entry_count"] = serde_json::json!(0);
    wrong_count["publication"]["receipt_entry_count"] = serde_json::json!(0);
    tampered.push((
        "entry count",
        LEGACY_PENDING_PUBLICATION_RECEIPT.as_bytes().to_vec(),
        wrong_count,
    ));
    let mut wrong_publication_count = intent.clone();
    wrong_publication_count["pending_publication_count"] = serde_json::json!(1);
    tampered.push((
        "publication count",
        LEGACY_PENDING_PUBLICATION_RECEIPT.as_bytes().to_vec(),
        wrong_publication_count,
    ));
    let mut wrong_manifest_path = intent.clone();
    wrong_manifest_path["manifest_path"] = serde_json::json!(different_path("other-machine.toml"));
    tampered.push((
        "manifest path",
        LEGACY_PENDING_PUBLICATION_RECEIPT.as_bytes().to_vec(),
        wrong_manifest_path,
    ));
    let mut wrong_manifest_digest = intent.clone();
    wrong_manifest_digest["before_manifest_sha256"] =
        serde_json::json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    tampered.push((
        "manifest digest",
        LEGACY_PENDING_PUBLICATION_RECEIPT.as_bytes().to_vec(),
        wrong_manifest_digest,
    ));
    let mut wrong_manifest_principal = intent.clone();
    wrong_manifest_principal["manifest_worker_principal"]["name"] =
        serde_json::json!("other-worker");
    tampered.push((
        "manifest principal",
        LEGACY_PENDING_PUBLICATION_RECEIPT.as_bytes().to_vec(),
        wrong_manifest_principal,
    ));
    let mut wrong_publication_link = intent.clone();
    wrong_publication_link["publication"]["pending"][0]["entry_id"] =
        serde_json::json!("019cafd0-5c00-7000-8000-000000000129");
    tampered.push((
        "publication link",
        LEGACY_PENDING_PUBLICATION_RECEIPT.as_bytes().to_vec(),
        wrong_publication_link,
    ));
    let mut wrong_prefix: serde_json::Value =
        serde_json::from_str(LEGACY_PENDING_PUBLICATION_RECEIPT).unwrap();
    wrong_prefix["entries"][0]["timestamp"] = serde_json::json!("2026-09-02T10:21:09Z");
    let mut wrong_prefix_bytes = serde_json::to_vec_pretty(&wrong_prefix).unwrap();
    wrong_prefix_bytes.push(b'\n');
    tampered.push(("receipt prefix", wrong_prefix_bytes, intent.clone()));

    for (label, receipt_bytes, intent_document) in tampered {
        fs::write(fixture.receipt_path(), &receipt_bytes).unwrap();
        let mut tampered_intent_bytes = serde_json::to_vec_pretty(&intent_document).unwrap();
        tampered_intent_bytes.push(b'\n');
        fs::write(&intent_path, &tampered_intent_bytes).unwrap();

        let error = crate::setup::pending::publish_manifest(
            &crate::manifest::MachineManifestStore::new_for_test(&manifest_path),
            &receipt_store,
            &mut draft,
            report.completion(),
            &mut ReceiptMetadataSource::for_test([]),
        )
        .unwrap_err();

        assert_eq!(error.error_code(), "setup.receipt_conflict", "{label}");
        assert_eq!(error.exit_code().as_i32(), 13, "{label}");
        assert_eq!(
            fs::read(fixture.receipt_path()).unwrap(),
            receipt_bytes,
            "{label}"
        );
        assert_eq!(
            fs::read(&intent_path).unwrap(),
            tampered_intent_bytes,
            "{label}"
        );
        assert!(!manifest_path.exists(), "{label}");
        assert!(state.lock().unwrap().is_empty(), "{label}");
    }

    fs::write(
        fixture.receipt_path(),
        LEGACY_PENDING_PUBLICATION_RECEIPT.as_bytes(),
    )
    .unwrap();
    fs::write(&intent_path, intent_bytes).unwrap();

    let rerun = apply_plan_with_journal(
        &mut plan,
        &receipt_store,
        &mut ReceiptMetadataSource::for_test([]),
    )
    .unwrap();
    crate::setup::pending::publish_manifest(
        &crate::manifest::MachineManifestStore::new_for_test(&manifest_path),
        &receipt_store,
        &mut draft,
        rerun.completion(),
        &mut ReceiptMetadataSource::for_test([]),
    )
    .unwrap();

    assert_eq!(state.lock().unwrap().len(), 0);
    assert!(!intent_path.exists());
    assert!(manifest_path.exists());
    let checkpoint = fs::read(fixture.receipt_path()).unwrap();
    assert_ne!(checkpoint, LEGACY_PENDING_PUBLICATION_RECEIPT.as_bytes());
    let checkpoint: serde_json::Value = serde_json::from_slice(&checkpoint).unwrap();
    assert_eq!(
        checkpoint["entries"][0]["directories_created"],
        serde_json::json!([])
    );
    assert_eq!(
        checkpoint["pending_publications"][0]["publication_id"],
        "019cafd0-5c00-7000-8000-000000000122"
    );
}

#[test]
fn failed_receipt_checkpoint_leaves_a_valid_manifest_and_repairs_without_duplication() {
    let fixture = JournalFixture::new("pending-checkpoint-recovery");
    let receipt_path = fixture.receipt_path().to_path_buf();
    let receipt_store = ReceiptStore::new_for_test(receipt_path.clone());
    let manifest_path = fixture.root.join("machine.toml");
    let pending = NeedsHuman::new(
        HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
        None,
    );
    let mut plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            Arc::new(Mutex::new(Vec::new())),
            pending,
        )
        .0,
    ];
    let mut entry_metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000021",
        "2026-09-02T10:04:00Z",
    )]);
    let report = apply_plan_with_journal(&mut plan, &receipt_store, &mut entry_metadata).unwrap();
    let mut draft = pending_manifest_draft();
    let manifest_store = crate::manifest::MachineManifestStore::new_for_test(&manifest_path);
    let failing_receipt = ReceiptStore::new_for_test_failing_before_replace(receipt_path);
    let mut checkpoint_metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000022",
        "2026-09-02T10:04:01Z",
    )]);

    let error = crate::setup::pending::publish_manifest(
        &manifest_store,
        &failing_receipt,
        &mut draft,
        report.completion(),
        &mut checkpoint_metadata,
    )
    .unwrap_err();

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code().as_i32(), 13);
    assert!(draft.pending_actions.is_none());
    assert_eq!(
        manifest_store
            .read()
            .unwrap()
            .manifest
            .pending_actions
            .unwrap()[0]
            .id,
        "test.local-approval"
    );
    let after_failure: serde_json::Value =
        serde_json::from_slice(&receipt_store.read_snapshot().unwrap().to_json().unwrap()).unwrap();
    assert_eq!(after_failure["entries"].as_array().unwrap().len(), 1);
    assert!(after_failure["pending_publications"].is_null());
    assert!(fixture.pending_publication_intent_path().exists());

    let mut no_entry_metadata = ReceiptMetadataSource::for_test([]);
    let rerun = apply_plan_with_journal(&mut plan, &receipt_store, &mut no_entry_metadata).unwrap();
    let mut repair_metadata = ReceiptMetadataSource::for_test([]);
    crate::setup::pending::publish_manifest(
        &crate::manifest::MachineManifestStore::new_with_failing_publication_replace(
            &manifest_path,
        ),
        &receipt_store,
        &mut draft,
        rerun.completion(),
        &mut repair_metadata,
    )
    .unwrap();
    assert!(!fixture.pending_publication_intent_path().exists());
    let repaired: serde_json::Value =
        serde_json::from_slice(&receipt_store.read_snapshot().unwrap().to_json().unwrap()).unwrap();
    assert_eq!(repaired["entries"].as_array().unwrap().len(), 1);
    assert_eq!(
        repaired["pending_publications"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        repaired["pending_publications"][0]["pending"][0]["entry_id"],
        "019cafd0-5c00-7000-8000-000000000021"
    );
}

#[cfg(not(target_os = "windows"))]
#[test]
fn manifest_parent_sync_precedes_checkpoint_and_exact_after_recovery_resyncs_without_rewrite() {
    let fixture = JournalFixture::new("pending-manifest-parent-sync");
    let receipt_store = ReceiptStore::new_for_test(fixture.receipt_path());
    let manifest_path = fixture.root.join("machine.toml");
    let mut plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            Arc::new(Mutex::new(Vec::new())),
            NeedsHuman::new(
                HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
                None,
            ),
        )
        .0,
    ];
    let report = apply_plan_with_journal(
        &mut plan,
        &receipt_store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000071",
            "2026-09-02T10:09:00Z",
        )]),
    )
    .unwrap();
    let mut draft = pending_manifest_draft();
    let failing_sync =
        crate::manifest::MachineManifestStore::new_with_failing_pending_parent_sync(&manifest_path);

    let error = crate::setup::pending::publish_manifest(
        &failing_sync,
        &receipt_store,
        &mut draft,
        report.completion(),
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000072",
            "2026-09-02T10:09:01Z",
        )]),
    )
    .unwrap_err();

    assert_eq!(error.error_code(), "setup.apply_failed");
    assert_eq!(error.exit_code().as_i32(), 13);
    let published_manifest = fs::read(&manifest_path).unwrap();
    assert!(fixture.pending_publication_intent_path().exists());
    let receipt_after_sync_failure: serde_json::Value =
        serde_json::from_slice(&receipt_store.read_snapshot().unwrap().to_json().unwrap()).unwrap();
    assert!(receipt_after_sync_failure["pending_publications"].is_null());

    let recovery = apply_plan_with_journal(
        &mut plan,
        &receipt_store,
        &mut ReceiptMetadataSource::for_test([]),
    )
    .unwrap();

    let recovery_error = crate::setup::pending::publish_manifest(
        &failing_sync,
        &receipt_store,
        &mut draft,
        recovery.completion(),
        &mut ReceiptMetadataSource::for_test([]),
    )
    .unwrap_err();
    assert_eq!(recovery_error.error_code(), "setup.apply_failed");
    assert_eq!(fs::read(&manifest_path).unwrap(), published_manifest);
    assert!(fixture.pending_publication_intent_path().exists());
    assert!(serde_json::from_slice::<serde_json::Value>(
        &receipt_store.read_snapshot().unwrap().to_json().unwrap()
    )
    .unwrap()["pending_publications"]
        .is_null());

    crate::setup::pending::publish_manifest(
        &crate::manifest::MachineManifestStore::new_with_failing_publication_replace(
            &manifest_path,
        ),
        &receipt_store,
        &mut draft,
        recovery.completion(),
        &mut ReceiptMetadataSource::for_test([]),
    )
    .unwrap();

    assert_eq!(fs::read(&manifest_path).unwrap(), published_manifest);
    assert!(!fixture.pending_publication_intent_path().exists());
    let repaired: serde_json::Value =
        serde_json::from_slice(&receipt_store.read_snapshot().unwrap().to_json().unwrap()).unwrap();
    assert_eq!(
        repaired["pending_publications"].as_array().unwrap().len(),
        1
    );
}

#[test]
fn pending_publication_intent_faults_retain_only_unambiguous_evidence() {
    type FailingStore = fn(PathBuf) -> ReceiptStore;
    let cases: [(&str, FailingStore, bool, bool); 3] = [
        (
            "during-write",
            ReceiptStore::new_for_test_failing_pending_intent_during_write,
            false,
            false,
        ),
        (
            "before-publish",
            ReceiptStore::new_for_test_failing_pending_intent_before_publish,
            false,
            true,
        ),
        (
            "after-publish",
            ReceiptStore::new_for_test_failing_pending_intent_after_publish,
            true,
            false,
        ),
    ];

    for (name, failing_store, final_exists, temporary_is_complete) in cases {
        let fixture = JournalFixture::new(&format!("pending-intent-{name}"));
        let receipt_store = ReceiptStore::new_for_test(fixture.receipt_path());
        let manifest_path = fixture.root.join("machine.toml");
        let mut plan = vec![
            Action::test_named_needs_human(
                "test.local-approval",
                Privilege::None,
                Arc::new(Mutex::new(Vec::new())),
                NeedsHuman::new(
                    HumanInstructions::new("Complete the local approval, then rerun setup.")
                        .unwrap(),
                    None,
                ),
            )
            .0,
        ];
        let report = apply_plan_with_journal(
            &mut plan,
            &receipt_store,
            &mut ReceiptMetadataSource::for_test([(
                "019cafd0-5c00-7000-8000-000000000081",
                "2026-09-02T10:10:00Z",
            )]),
        )
        .unwrap();
        let mut draft = pending_manifest_draft();
        let publication_id = "019cafd0-5c00-7000-8000-000000000082";

        let error = crate::setup::pending::publish_manifest(
            &crate::manifest::MachineManifestStore::new_for_test(&manifest_path),
            &failing_store(fixture.receipt_path().to_path_buf()),
            &mut draft,
            report.completion(),
            &mut ReceiptMetadataSource::for_test([(publication_id, "2026-09-02T10:10:01Z")]),
        )
        .unwrap_err();

        assert_eq!(error.error_code(), "setup.receipt_conflict");
        assert_eq!(error.exit_code().as_i32(), 13);
        assert!(!manifest_path.exists());
        let receipt: serde_json::Value =
            serde_json::from_slice(&receipt_store.read_snapshot().unwrap().to_json().unwrap())
                .unwrap();
        assert!(receipt["pending_publications"].is_null());
        let intent = fixture.pending_publication_intent_path();
        assert_eq!(intent.exists(), final_exists);
        if final_exists {
            serde_json::from_slice::<serde_json::Value>(&fs::read(&intent).unwrap()).unwrap();
        }
        let temporary = fixture.pending_publication_temporary_path(publication_id);
        assert_eq!(temporary.exists(), !final_exists);
        if temporary_is_complete {
            serde_json::from_slice::<serde_json::Value>(&fs::read(&temporary).unwrap()).unwrap();
        } else if temporary.exists() {
            assert!(
                serde_json::from_slice::<serde_json::Value>(&fs::read(&temporary).unwrap())
                    .is_err()
            );
        }
    }
}

#[test]
fn pending_publication_intent_reader_observes_only_absent_or_complete_documents() {
    for after_publish in [false, true] {
        let suffix = if after_publish {
            "after-publish"
        } else {
            "during-write"
        };
        let fixture = JournalFixture::new(&format!("pending-intent-reader-{suffix}"));
        let receipt_store = ReceiptStore::new_for_test(fixture.receipt_path());
        let manifest_path = fixture.root.join("machine.toml");
        let mut plan = vec![
            Action::test_named_needs_human(
                "test.local-approval",
                Privilege::None,
                Arc::new(Mutex::new(Vec::new())),
                NeedsHuman::new(
                    HumanInstructions::new("Complete the local approval, then rerun setup.")
                        .unwrap(),
                    None,
                ),
            )
            .0,
        ];
        let report = apply_plan_with_journal(
            &mut plan,
            &receipt_store,
            &mut ReceiptMetadataSource::for_test([(
                "019cafd0-5c00-7000-8000-000000000091",
                "2026-09-02T10:11:00Z",
            )]),
        )
        .unwrap();
        let entered = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let paused_store = if after_publish {
            ReceiptStore::new_for_test_pausing_pending_intent_after_publish(
                fixture.receipt_path(),
                Arc::clone(&entered),
                Arc::clone(&resume),
            )
        } else {
            ReceiptStore::new_for_test_pausing_pending_intent_during_write(
                fixture.receipt_path(),
                Arc::clone(&entered),
                Arc::clone(&resume),
            )
        };

        std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                let mut draft = pending_manifest_draft();
                crate::setup::pending::publish_manifest(
                    &crate::manifest::MachineManifestStore::new_for_test(&manifest_path),
                    &paused_store,
                    &mut draft,
                    report.completion(),
                    &mut ReceiptMetadataSource::for_test([(
                        "019cafd0-5c00-7000-8000-000000000092",
                        "2026-09-02T10:11:01Z",
                    )]),
                )
            });
            entered.wait();
            let intent_visible = fixture.pending_publication_intent_path().exists();
            let temporary_visible = fixture
                .pending_publication_temporary_path("019cafd0-5c00-7000-8000-000000000092")
                .exists();
            let manifest_visible = manifest_path.exists();
            let intent_bytes =
                intent_visible.then(|| fs::read(fixture.pending_publication_intent_path()));
            let observed = receipt_store.read_snapshot();
            resume.wait();
            writer.join().unwrap().unwrap();

            assert_eq!(intent_visible, after_publish);
            assert_eq!(temporary_visible, !after_publish);
            assert!(!manifest_visible);
            if let Some(intent_bytes) = intent_bytes {
                serde_json::from_slice::<serde_json::Value>(&intent_bytes.unwrap()).unwrap();
            }
            observed.unwrap();
        });
    }
}

#[test]
fn pending_publication_displaced_temporary_after_create_retains_all_evidence() {
    let fixture = JournalFixture::new("pending-intent-displaced-temporary");
    let receipt_store = ReceiptStore::new_for_test(fixture.receipt_path());
    let manifest_path = fixture.root.join("machine.toml");
    let mut plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            Arc::new(Mutex::new(Vec::new())),
            NeedsHuman::new(
                HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
                None,
            ),
        )
        .0,
    ];
    let report = apply_plan_with_journal(
        &mut plan,
        &receipt_store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-0000000000a1",
            "2026-09-02T10:11:30Z",
        )]),
    )
    .unwrap();
    let publication_id = "019cafd0-5c00-7000-8000-0000000000a2";
    let temporary = fixture.pending_publication_temporary_path(publication_id);
    let displaced = temporary.with_extension("created-by-styrn");
    let victim = b"unrelated temporary evidence";
    let entered = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    let paused_store = ReceiptStore::new_for_test_pausing_pending_intent_after_create(
        fixture.receipt_path(),
        Arc::clone(&entered),
        Arc::clone(&resume),
    );

    let publication = std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            crate::setup::pending::publish_manifest(
                &crate::manifest::MachineManifestStore::new_for_test(&manifest_path),
                &paused_store,
                &mut pending_manifest_draft(),
                report.completion(),
                &mut ReceiptMetadataSource::for_test([(publication_id, "2026-09-02T10:11:31Z")]),
            )
        });
        entered.wait();
        let displacement = (|| -> std::io::Result<()> {
            fs::rename(&temporary, &displaced)?;
            fs::write(&temporary, victim)?;
            make_private(&temporary);
            Ok(())
        })();
        resume.wait();
        let publication = writer.join().unwrap();
        displacement.unwrap();
        publication
    });
    let error = publication.unwrap_err();

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code().as_i32(), 13);
    assert_eq!(fs::read(&temporary).unwrap(), victim);
    serde_json::from_slice::<serde_json::Value>(&fs::read(&displaced).unwrap()).unwrap();
    assert!(!fixture.pending_publication_intent_path().exists());
    assert!(!manifest_path.exists());
    let receipt: serde_json::Value =
        serde_json::from_slice(&receipt_store.read_snapshot().unwrap().to_json().unwrap()).unwrap();
    assert!(receipt["pending_publications"].is_null());
}

#[test]
fn pending_publication_conflict_retains_raced_preexisting_evidence() {
    let fixture = JournalFixture::new("pending-intent-raced-evidence");
    let receipt_store = ReceiptStore::new_for_test(fixture.receipt_path());
    let manifest_path = fixture.root.join("machine.toml");
    let mut plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            Arc::new(Mutex::new(Vec::new())),
            NeedsHuman::new(
                HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
                None,
            ),
        )
        .0,
    ];
    let report = apply_plan_with_journal(
        &mut plan,
        &receipt_store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000101",
            "2026-09-02T10:12:00Z",
        )]),
    )
    .unwrap();
    let entered = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    let paused_store = ReceiptStore::new_for_test_pausing_pending_intent_before_publish(
        fixture.receipt_path(),
        Arc::clone(&entered),
        Arc::clone(&resume),
    );

    let publication = std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            let mut draft = pending_manifest_draft();
            crate::setup::pending::publish_manifest(
                &crate::manifest::MachineManifestStore::new_for_test(&manifest_path),
                &paused_store,
                &mut draft,
                report.completion(),
                &mut ReceiptMetadataSource::for_test([(
                    "019cafd0-5c00-7000-8000-000000000102",
                    "2026-09-02T10:12:01Z",
                )]),
            )
        });
        entered.wait();
        fs::write(
            fixture.pending_publication_intent_path(),
            b"{\"incomplete\":",
        )
        .unwrap();
        make_private(&fixture.pending_publication_intent_path());
        resume.wait();
        writer.join().unwrap()
    });
    let error = publication.unwrap_err();

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code().as_i32(), 13);
    assert_eq!(
        fs::read(fixture.pending_publication_intent_path()).unwrap(),
        b"{\"incomplete\":"
    );
    let retained_temporary =
        fixture.pending_publication_temporary_path("019cafd0-5c00-7000-8000-000000000102");
    serde_json::from_slice::<serde_json::Value>(&fs::read(&retained_temporary).unwrap()).unwrap();
    assert!(!manifest_path.exists());

    let preexisting_error = crate::setup::pending::publish_manifest(
        &crate::manifest::MachineManifestStore::new_for_test(&manifest_path),
        &receipt_store,
        &mut pending_manifest_draft(),
        report.completion(),
        &mut ReceiptMetadataSource::for_test([]),
    )
    .unwrap_err();
    assert_eq!(preexisting_error.error_code(), "setup.receipt_conflict");
    assert_eq!(
        fs::read(fixture.pending_publication_intent_path()).unwrap(),
        b"{\"incomplete\":"
    );
    serde_json::from_slice::<serde_json::Value>(&fs::read(&retained_temporary).unwrap()).unwrap();
    assert!(!manifest_path.exists());
}

#[cfg(not(target_os = "windows"))]
#[test]
fn unix_pending_publication_recovery_removes_only_the_bound_orphan_temporary_link() {
    let fixture = JournalFixture::new("pending-intent-orphan-link");
    let receipt_store = ReceiptStore::new_for_test(fixture.receipt_path());
    let manifest_path = fixture.root.join("machine.toml");
    let mut plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            Arc::new(Mutex::new(Vec::new())),
            NeedsHuman::new(
                HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
                None,
            ),
        )
        .0,
    ];
    let report = apply_plan_with_journal(
        &mut plan,
        &receipt_store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000111",
            "2026-09-02T10:13:00Z",
        )]),
    )
    .unwrap();
    let publication_id = "019cafd0-5c00-7000-8000-000000000112";
    let mut draft = pending_manifest_draft();

    let error = crate::setup::pending::publish_manifest(
        &crate::manifest::MachineManifestStore::new_for_test(&manifest_path),
        &ReceiptStore::new_for_test_crashing_pending_intent_after_durable_publish(
            fixture.receipt_path(),
        ),
        &mut draft,
        report.completion(),
        &mut ReceiptMetadataSource::for_test([(publication_id, "2026-09-02T10:13:01Z")]),
    )
    .unwrap_err();

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    let repair = apply_plan_with_journal(
        &mut plan,
        &receipt_store,
        &mut ReceiptMetadataSource::for_test([]),
    )
    .unwrap();
    let intent_path = fixture.pending_publication_intent_path();
    let temporary_path = fixture.pending_publication_temporary_path(publication_id);
    // Reproduce the exact Unix power-loss state after the final link's
    // directory fsync and before verified retirement of the temporary link.
    fs::hard_link(&intent_path, &temporary_path).unwrap();
    assert_eq!(
        crate::platform::private_file_identity(&intent_path).unwrap(),
        crate::platform::private_file_identity(&temporary_path).unwrap()
    );
    let intent_bytes = fs::read(&intent_path).unwrap();
    serde_json::from_slice::<serde_json::Value>(&intent_bytes).unwrap();
    assert!(!manifest_path.exists());

    let displaced = temporary_path.with_extension("bound");
    fs::rename(&temporary_path, &displaced).unwrap();
    fs::write(&temporary_path, b"unrelated temporary evidence").unwrap();
    make_private(&temporary_path);
    let recovery_error = crate::setup::pending::publish_manifest(
        &crate::manifest::MachineManifestStore::new_for_test(&manifest_path),
        &receipt_store,
        &mut draft,
        repair.completion(),
        &mut ReceiptMetadataSource::for_test([]),
    )
    .unwrap_err();
    assert_eq!(recovery_error.error_code(), "setup.receipt_conflict");
    assert_eq!(fs::read(&intent_path).unwrap(), intent_bytes);
    assert_eq!(
        fs::read(&temporary_path).unwrap(),
        b"unrelated temporary evidence"
    );
    assert!(!manifest_path.exists());

    let unrelated = temporary_path.with_extension("unrelated");
    fs::rename(&temporary_path, &unrelated).unwrap();
    fs::rename(displaced, &temporary_path).unwrap();
    crate::setup::pending::publish_manifest(
        &crate::manifest::MachineManifestStore::new_for_test(&manifest_path),
        &receipt_store,
        &mut draft,
        repair.completion(),
        &mut ReceiptMetadataSource::for_test([]),
    )
    .unwrap();

    assert!(!intent_path.exists());
    assert!(!temporary_path.exists());
    assert_eq!(
        fs::read(unrelated).unwrap(),
        b"unrelated temporary evidence"
    );
    assert!(manifest_path.exists());
    let repaired: serde_json::Value =
        serde_json::from_slice(&receipt_store.read_snapshot().unwrap().to_json().unwrap()).unwrap();
    assert_eq!(
        repaired["pending_publications"].as_array().unwrap().len(),
        1
    );
}

#[test]
fn resolved_publication_intent_prevents_immediate_recurrence_suppression() {
    let fixture = JournalFixture::new("pending-resolution-intent-recurrence");
    let receipt_path = fixture.receipt_path().to_path_buf();
    let receipt_store = ReceiptStore::new_for_test(&receipt_path);
    let manifest_path = fixture.root.join("machine.toml");
    let manifest_store = crate::manifest::MachineManifestStore::new_for_test(&manifest_path);
    let needs_human = NeedsHuman::new(
        HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
        None,
    );
    let mut initial_plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            Arc::new(Mutex::new(Vec::new())),
            needs_human.clone(),
        )
        .0,
    ];
    let mut initial_metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000041",
        "2026-09-02T10:06:00Z",
    )]);
    let initial =
        apply_plan_with_journal(&mut initial_plan, &receipt_store, &mut initial_metadata).unwrap();
    let mut draft = pending_manifest_draft();
    crate::setup::pending::publish_manifest(
        &manifest_store,
        &receipt_store,
        &mut draft,
        initial.completion(),
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000042",
            "2026-09-02T10:06:01Z",
        )]),
    )
    .unwrap();

    let mut resolved_plan = Vec::new();
    let resolved = apply_plan_with_journal(
        &mut resolved_plan,
        &receipt_store,
        &mut ReceiptMetadataSource::for_test([]),
    )
    .unwrap();
    let error = crate::setup::pending::publish_manifest(
        &manifest_store,
        &ReceiptStore::new_for_test_failing_before_replace(receipt_path),
        &mut draft,
        resolved.completion(),
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000043",
            "2026-09-02T10:06:02Z",
        )]),
    )
    .unwrap_err();

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert!(fixture.pending_publication_intent_path().exists());
    assert!(manifest_store
        .read()
        .unwrap()
        .manifest
        .pending_actions
        .is_none());

    let mut recurrence_plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            Arc::new(Mutex::new(Vec::new())),
            needs_human,
        )
        .0,
    ];
    let recurrence = apply_plan_with_journal(
        &mut recurrence_plan,
        &receipt_store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000044",
            "2026-09-02T10:06:03Z",
        )]),
    )
    .unwrap();
    assert_eq!(receipt_store.read_snapshot().unwrap().entry_count(), 2);

    crate::setup::pending::publish_manifest(
        &manifest_store,
        &receipt_store,
        &mut draft,
        recurrence.completion(),
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000045",
            "2026-09-02T10:06:04Z",
        )]),
    )
    .unwrap();

    let receipt: serde_json::Value =
        serde_json::from_slice(&receipt_store.read_snapshot().unwrap().to_json().unwrap()).unwrap();
    assert_eq!(receipt["pending_publications"].as_array().unwrap().len(), 3);
    assert_eq!(
        receipt["pending_publications"][0]["pending"][0]["entry_id"],
        "019cafd0-5c00-7000-8000-000000000041"
    );
    assert_eq!(
        receipt["pending_publications"][1]["pending"],
        serde_json::json!([])
    );
    assert_eq!(
        receipt["pending_publications"][2]["pending"][0]["entry_id"],
        "019cafd0-5c00-7000-8000-000000000044"
    );
    assert!(!fixture.pending_publication_intent_path().exists());
}

#[test]
fn publication_recovery_rejects_a_third_manifest_digest_and_retains_evidence() {
    let fixture = JournalFixture::new("pending-publication-third-digest");
    let receipt_store = ReceiptStore::new_for_test(fixture.receipt_path());
    let manifest_path = fixture.root.join("machine.toml");
    let manifest_store = crate::manifest::MachineManifestStore::new_for_test(&manifest_path);
    let mut draft = pending_manifest_draft();
    manifest_store.write_generated(&draft).unwrap();
    let mut plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            Arc::new(Mutex::new(Vec::new())),
            NeedsHuman::new(
                HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
                None,
            ),
        )
        .0,
    ];
    let report = apply_plan_with_journal(
        &mut plan,
        &receipt_store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000051",
            "2026-09-02T10:07:00Z",
        )]),
    )
    .unwrap();

    crate::setup::pending::publish_manifest(
        &crate::manifest::MachineManifestStore::new_with_failing_publication_replace(
            &manifest_path,
        ),
        &receipt_store,
        &mut draft,
        report.completion(),
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000052",
            "2026-09-02T10:07:01Z",
        )]),
    )
    .unwrap_err();
    assert!(fixture.pending_publication_intent_path().exists());

    let mut third = draft.clone();
    third.name = "third-valid-manifest-state".to_owned();
    manifest_store.write_generated(&third).unwrap();
    let third_bytes = fs::read(&manifest_path).unwrap();
    let receipt_before = receipt_store.read_snapshot().unwrap().to_json().unwrap();

    let error = crate::setup::pending::publish_manifest(
        &manifest_store,
        &receipt_store,
        &mut draft,
        report.completion(),
        &mut ReceiptMetadataSource::for_test([]),
    )
    .unwrap_err();

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code().as_i32(), 13);
    assert_eq!(fs::read(&manifest_path).unwrap(), third_bytes);
    assert_eq!(
        receipt_store.read_snapshot().unwrap().to_json().unwrap(),
        receipt_before
    );
    assert!(fixture.pending_publication_intent_path().exists());
}

#[test]
fn applied_append_preserves_a_prepared_publication_prefix_until_recovery() {
    let fixture = JournalFixture::new("pending-publication-applied-append");
    let receipt_store = ReceiptStore::new_for_test(fixture.receipt_path());
    let manifest_path = fixture.root.join("machine.toml");
    let manifest_store = crate::manifest::MachineManifestStore::new_for_test(&manifest_path);
    let mut draft = pending_manifest_draft();
    manifest_store.write_generated(&draft).unwrap();
    let mut pending_plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            Arc::new(Mutex::new(Vec::new())),
            NeedsHuman::new(
                HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
                None,
            ),
        )
        .0,
    ];
    let pending = apply_plan_with_journal(
        &mut pending_plan,
        &receipt_store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000061",
            "2026-09-02T10:08:00Z",
        )]),
    )
    .unwrap();
    crate::setup::pending::publish_manifest(
        &crate::manifest::MachineManifestStore::new_with_failing_publication_replace(
            &manifest_path,
        ),
        &receipt_store,
        &mut draft,
        pending.completion(),
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000062",
            "2026-09-02T10:08:01Z",
        )]),
    )
    .unwrap_err();
    assert!(fixture.pending_publication_intent_path().exists());

    let state = Arc::new(Mutex::new(Vec::new()));
    let mut applied_plan = vec![
        Action::test_journaled_state("test.applied", 1, Privilege::None, Arc::clone(&state)).0,
    ];
    apply_plan_with_journal(
        &mut applied_plan,
        &receipt_store,
        &mut ReceiptMetadataSource::for_test([(
            "019cafd0-5c00-7000-8000-000000000063",
            "2026-09-02T10:08:02Z",
        )]),
    )
    .unwrap();

    let recovery = apply_plan_with_journal(
        &mut pending_plan,
        &receipt_store,
        &mut ReceiptMetadataSource::for_test([]),
    )
    .unwrap();

    crate::setup::pending::publish_manifest(
        &manifest_store,
        &receipt_store,
        &mut draft,
        recovery.completion(),
        &mut ReceiptMetadataSource::for_test([]),
    )
    .unwrap();

    let receipt: serde_json::Value =
        serde_json::from_slice(&receipt_store.read_snapshot().unwrap().to_json().unwrap()).unwrap();
    assert_eq!(receipt["entries"].as_array().unwrap().len(), 2);
    assert_eq!(receipt["entries"][1]["status"], "applied");
    assert_eq!(receipt["pending_publications"].as_array().unwrap().len(), 1);
    assert_eq!(receipt["pending_publications"][0]["receipt_entry_count"], 1);
    assert_eq!(*state.lock().unwrap(), vec![1]);
    assert!(!fixture.pending_publication_intent_path().exists());
}

#[test]
fn concurrent_publication_of_one_token_allows_one_checkpoint_and_rejects_stale_reuse() {
    let fixture = JournalFixture::new("pending-publication-race");
    let receipt_path = fixture.receipt_path().to_path_buf();
    let receipt_store = ReceiptStore::new_for_test(&receipt_path);
    let manifest_path = fixture.root.join("machine.toml");
    let mut plan = vec![
        Action::test_named_needs_human(
            "test.local-approval",
            Privilege::None,
            Arc::new(Mutex::new(Vec::new())),
            NeedsHuman::new(
                HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
                None,
            ),
        )
        .0,
    ];
    let mut entry_metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000031",
        "2026-09-02T10:05:00Z",
    )]);
    let report = apply_plan_with_journal(&mut plan, &receipt_store, &mut entry_metadata).unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(2));

    let results = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for sequence in 32..=33 {
            let barrier = Arc::clone(&barrier);
            let receipt_path = receipt_path.clone();
            let manifest_path = manifest_path.clone();
            let completed = report.completion();
            handles.push(scope.spawn(move || {
                let mut draft = pending_manifest_draft();
                let checkpoint = if sequence == 32 {
                    (
                        "019cafd0-5c00-7000-8000-000000000032",
                        "2026-09-02T10:05:01Z",
                    )
                } else {
                    (
                        "019cafd0-5c00-7000-8000-000000000033",
                        "2026-09-02T10:05:02Z",
                    )
                };
                let mut metadata = ReceiptMetadataSource::for_test([checkpoint]);
                barrier.wait();
                crate::setup::pending::publish_manifest(
                    &crate::manifest::MachineManifestStore::new_for_test(manifest_path),
                    &ReceiptStore::new_for_test(receipt_path),
                    &mut draft,
                    completed,
                    &mut metadata,
                )
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                matches!(
                    result,
                    Err(crate::setup::pending::PendingError::Receipt(
                        ReceiptStoreError::IntentConflict
                    ))
                )
            })
            .count(),
        1
    );

    let receipt: serde_json::Value =
        serde_json::from_slice(&receipt_store.read_snapshot().unwrap().to_json().unwrap()).unwrap();
    assert_eq!(receipt["entries"].as_array().unwrap().len(), 1);
    assert_eq!(receipt["pending_publications"].as_array().unwrap().len(), 1);
    assert_eq!(
        receipt["pending_publications"][0]["pending"][0]["entry_id"],
        "019cafd0-5c00-7000-8000-000000000031"
    );
}

#[test]
fn pending_projection_rejects_duplicate_ids_without_partial_state_and_empty_policy_succeeds() {
    let fixture = JournalFixture::new("pending-duplicate-projection");
    let store = ReceiptStore::new_for_test(fixture.receipt_path());
    let state = Arc::new(Mutex::new(Vec::new()));
    let pending = NeedsHuman::new(
        HumanInstructions::new("Complete the local approval, then rerun setup.").unwrap(),
        None,
    );
    let mut plan = vec![
        Action::test_named_needs_human("test.local-approval", Privilege::None, state, pending).0,
    ];
    let mut metadata = ReceiptMetadataSource::for_test([(
        "019cafd0-5c00-7000-8000-000000000013",
        "2026-09-02T10:03:00Z",
    )]);
    let report = apply_plan_with_journal(&mut plan, &store, &mut metadata).unwrap();
    let duplicate = vec![report.pending()[0].clone(), report.pending()[0].clone()];
    let mut draft = pending_manifest_draft();

    let error =
        crate::setup::pending::project_manifest_for_test(&mut draft, &duplicate).unwrap_err();

    assert_eq!(error.error_code(), "setup.plan_invalid");
    assert_eq!(error.exit_code().as_i32(), 13);
    assert!(draft.pending_actions.is_none());

    let empty =
        apply_plan_with_journal(&mut [], &store, &mut ReceiptMetadataSource::for_test([])).unwrap();
    let outcome = crate::setup::pending::PendingPolicy::default()
        .evaluate(
            Utc.with_ymd_and_hms(2026, 9, 2, 10, 3, 1).unwrap(),
            empty.completion(),
        )
        .unwrap();
    assert_eq!(outcome.exit_code().as_i32(), 0);
    let json: serde_json::Value =
        serde_json::from_str(&crate::output::to_json(outcome.envelope()).unwrap()).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["data"]["pending"], serde_json::json!([]));
    assert_eq!(json["warnings"], serde_json::json!([]));
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
        &crate::platform::resolve_current_worker_principal().unwrap(),
    )
    .unwrap();
    crate::platform::harden_manifest_directory(
        fixture.receipt_path().parent().unwrap(),
        crate::platform::ManifestOwner::User,
        &crate::platform::resolve_current_worker_principal().unwrap(),
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
    let mut metadata = ReceiptMetadataSource::for_test([
        (
            "019cafd0-5c00-7000-8000-000000000002",
            "2026-09-02T10:00:01Z",
        ),
        (
            "019cafd0-5c00-7000-8000-000000000003",
            "2026-09-02T10:00:02Z",
        ),
    ]);

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
    assert_eq!(report.pending()[0].id().as_str(), "test.pending");
    assert_eq!(report.pending()[0].needs_human(), &pending);
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
        3
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
            "fields `directories_created`, `files_created`, `files_modified`, `services`, `accounts`, `registry_keys`, `firewall_rules` and `download_provenance` of struct `action::ActionEffect` are private",
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
fn setup_plan_cannot_construct_pending_actions() {
    assert_fixture_fails_with_cfg(
        "real_plan_apply.rs",
        &["plan_pending_forge_fixture"],
        FixtureExpectation::new(
            "E0624",
            "associated function `new` is private",
            5,
            Some("private associated function"),
            "hostile_pending.rs",
        ),
    );
}

#[test]
fn setup_plan_cannot_construct_pending_publication_authority() {
    assert_fixture_fails_with_cfg(
        "pending_publication_forge.rs",
        &["plan_pending_authority_forge_fixture"],
        FixtureExpectation::new(
            "E0603",
            "tuple struct constructor `PendingPublicationAuthority` is private",
            19,
            Some("private tuple struct constructor"),
            "hostile_pending_publication.rs",
        ),
    );
}

#[test]
fn setup_plan_cannot_call_real_pending_publisher_with_a_raw_slice() {
    assert_fixture_fails_with_cfg(
        "pending_publication_forge.rs",
        &["plan_pending_publication_forge_fixture"],
        FixtureExpectation::new(
            "E0308",
            "mismatched types",
            12,
            Some("expected `&CompletedExecutionToken`, found `&[_; 0]`"),
            "hostile_pending_publication.rs",
        ),
    );
}

#[test]
fn setup_plan_cannot_construct_a_completed_execution_token() {
    assert_fixture_fails_with_cfg(
        "pending_publication_forge.rs",
        &["plan_completed_execution_construct_fixture"],
        FixtureExpectation::new(
            "E0451",
            "fields `pending`, `occurrences` and `receipt` of struct `CompletedExecutionToken` are private",
            3,
            Some("private field"),
            "hostile_completed_execution_construct.rs",
        ),
    );
}

#[test]
fn setup_plan_cannot_modify_a_completed_execution_token() {
    assert_fixture_fails_with_cfg(
        "pending_publication_forge.rs",
        &["plan_completed_execution_mutate_fixture"],
        FixtureExpectation::new(
            "E0616",
            "field `pending` of struct `CompletedExecutionToken` is private",
            3,
            Some("private field"),
            "hostile_completed_execution_mutate.rs",
        ),
    );
}

#[test]
fn setup_plan_cannot_clone_a_completed_execution_token() {
    assert_fixture_fails_with_cfg(
        "pending_publication_forge.rs",
        &["plan_completed_execution_clone_fixture"],
        FixtureExpectation::new(
            "E0599",
            "no method named `clone` found for struct `CompletedExecutionToken` in the current scope",
            8,
            Some("method not found in `CompletedExecutionToken`"),
            "hostile_completed_execution_mutate.rs",
        ),
    );
}

#[test]
fn setup_plan_cannot_serialize_a_completed_execution_token() {
    assert_fixture_fails_with_cfg(
        "pending_publication_forge.rs",
        &["plan_completed_execution_serialize_fixture"],
        FixtureExpectation::new(
            "E0277",
            "the trait bound `CompletedExecutionToken: serde::Serialize` is not satisfied",
            13,
            Some("unsatisfied trait bound"),
            "hostile_completed_execution_mutate.rs",
        ),
    );
}

#[test]
fn setup_plan_cannot_project_pending_manifest_state_directly() {
    assert_fixture_fails_with_cfg(
        "pending_publication_forge.rs",
        &["plan_pending_projection_fixture"],
        FixtureExpectation::new(
            "E0603",
            "function `project_manifest` is private",
            2,
            Some("private function"),
            "hostile_pending_projection.rs",
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
    let full_setup_fixture = name == "pending_publication_forge.rs";
    if !full_journal_fixture && !full_setup_fixture {
        command.arg("--cfg").arg("action_core_fixture");
    } else if full_journal_fixture {
        command.arg("--cfg").arg("action_compile_fixture");
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
        "sha2",
        "thiserror",
        "toml",
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
                "sha2",
                "thiserror",
                "toml",
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
            "sha2",
            "thiserror",
            "toml",
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

fn pending_manifest_draft() -> crate::manifest::MachineManifestDraft {
    crate::manifest::MachineManifest::parse_toml(include_str!(
        "../../../examples/machine.controller-worker.toml"
    ))
    .unwrap()
    .without_machine_id()
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

    fn only_transaction_path_if_present(&self) -> Option<PathBuf> {
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
        assert!(paths.len() <= 1);
        paths.into_iter().next()
    }

    fn pending_publication_intent_path(&self) -> PathBuf {
        self.receipt
            .parent()
            .unwrap()
            .join(".receipt.json.pending-publication.json")
    }

    fn pending_publication_temporary_path(&self, publication_id: &str) -> PathBuf {
        self.receipt.parent().unwrap().join(format!(
            ".receipt.json.pending-publication.{publication_id}.tmp"
        ))
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
