use super::*;
use crate::setup::{
    action::{
        execution::{ApplyPlanError, DurableReceiptBinding, PreparedActionRunner},
        Action, ActionEffect, ActionError, HumanInstructions, MutationCompletion, NeedsHuman,
        PendingSeverity, PreparedExecutionError, Privilege, ScriptFragment, VerifiedActionEffect,
    },
    receipt::{ReceiptMetadataSource, ReceiptStore, ReceiptStoreError},
};
use chrono::{TimeZone, Utc};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

#[test]
fn native_authorization_classifies_denial_launch_failure_and_child_exit() {
    #[cfg(unix)]
    fn status(code: i32) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code << 8)
    }
    #[cfg(windows)]
    fn status(code: i32) -> std::process::ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code as u32)
    }

    assert!(classify_native_authorization(Ok(status(0))).is_ok());
    assert!(matches!(
        classify_native_authorization(Ok(status(13))),
        Err(AuthorizationInvocationError::ChildFailed {
            exit_code: Some(13)
        })
    ));
    assert!(matches!(
        classify_native_authorization(Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "cancelled",
        ))),
        Err(AuthorizationInvocationError::Failed)
    ));
    assert!(matches!(
        classify_native_authorization(Err(std::io::Error::other("launch"))),
        Err(AuthorizationInvocationError::Launch(_))
    ));
}

#[test]
fn authorization_policy_has_only_interactive_or_explicit_noninteractive_grants() {
    assert!(
        !AuthorizationOptions::from_policy(SystemAuthorizationPolicy::NotGranted, false)
            .unwrap()
            .should_invoke()
    );
    for policy in [
        SystemAuthorizationPolicy::InteractiveConsent,
        SystemAuthorizationPolicy::ExplicitNoninteractive,
    ] {
        assert!(AuthorizationOptions::from_policy(policy, false)
            .unwrap()
            .should_invoke());
        assert!(AuthorizationOptions::from_policy(policy, true).is_err());
    }
    assert!(
        !AuthorizationOptions::from_policy(SystemAuthorizationPolicy::NotGranted, true)
            .unwrap()
            .should_invoke()
    );
}

#[test]
fn production_authorization_context_captures_the_exact_current_executable() {
    let fixture = AuthorizationFixture::new("production-context");
    let principal = crate::platform::resolve_current_worker_principal().unwrap();
    let context = AuthorizationContext::capture(
        "host-01",
        fixture.request_path().to_owned(),
        principal.clone(),
    )
    .unwrap();
    assert_eq!(context.executable(), std::env::current_exe().unwrap());
    assert_eq!(context.principal, principal);
}

#[test]
fn production_native_entrypoint_applies_user_plan_without_authorization() {
    let fixture = AuthorizationFixture::new("production-rootless");
    let store = ReceiptStore::new_user_for_test(fixture.user_receipt());
    let state = Arc::new(Mutex::new(Vec::new()));
    let mut plan = vec![
        Action::test_journaled_state("test.user-action", 1, Privilege::None, Arc::clone(&state)).0,
    ];
    let mut metadata = receipt_metadata(&[(
        "019cb047-3c00-7000-8000-000000000001",
        "2026-09-02T12:00:00Z",
    )]);

    let report = execute_with_native_authorization(
        &mut plan,
        &store,
        &mut metadata,
        NativeAuthorizationInput::new(
            "host-019cb047",
            fixture.request_path().to_owned(),
            crate::platform::resolve_current_worker_principal().unwrap(),
            SystemAuthorizationPolicy::NotGranted,
            false,
        ),
    )
    .unwrap();

    assert_eq!(*state.lock().unwrap(), vec![1]);
    assert_eq!(report.ordinary().applied_count(), 1);
    assert_eq!(report.privileged_status(), PrivilegedStatus::NotNeeded);
    assert!(report.everything_ready());
    assert!(!fixture.request_path().exists());
}

#[test]
fn current_user_worker_directory_never_requests_authorization() {
    let fixture = AuthorizationFixture::new("worker-directory-zero-authorization");
    let principal = crate::platform::resolve_current_worker_principal().unwrap();
    let setup_context = crate::platform::SetupExecutionContext::new_for_test(
        crate::platform::SetupHostPrivilege::Ordinary,
        principal.clone(),
    );
    let root = fixture.root.join("worker-root");
    let (mut plan, layout) = super::super::current_user_worker_directory_plan_for_test(
        &setup_context,
        root,
        Some(fixture.root.clone()),
    )
    .unwrap();
    assert_eq!(plan.len(), 6);
    assert!(plan
        .iter()
        .all(|action| action.privilege() == Privilege::None));
    let store = ReceiptStore::new_user_for_test_with_worker_layout(fixture.user_receipt(), layout);
    let mut metadata = ReceiptMetadataSource::for_test([
        (
            "019cb090-3400-7000-8000-000000000101",
            "2026-09-03T12:10:00Z",
        ),
        (
            "019cb090-3400-7000-8000-000000000102",
            "2026-09-03T12:10:01Z",
        ),
        (
            "019cb090-3400-7000-8000-000000000103",
            "2026-09-03T12:10:02Z",
        ),
        (
            "019cb090-3400-7000-8000-000000000104",
            "2026-09-03T12:10:03Z",
        ),
        (
            "019cb090-3400-7000-8000-000000000105",
            "2026-09-03T12:10:04Z",
        ),
        (
            "019cb090-3400-7000-8000-000000000106",
            "2026-09-03T12:10:05Z",
        ),
    ]);
    let mut invoker = SpyInvoker::default();

    let report = execute_with_authorization(
        &mut plan,
        &store,
        &mut metadata,
        &fixture.context(),
        AuthorizationOptions::noninteractive_yes(),
        &mut invoker,
    )
    .unwrap();

    assert_eq!(report.ordinary().applied_count(), 6);
    assert_eq!(report.privileged_status(), PrivilegedStatus::NotNeeded);
    assert!(report.everything_ready());
    assert_eq!(invoker.calls(), 0);
    assert!(!fixture.request_path().exists());
}

#[test]
fn current_user_worker_directory_creates_no_account() {
    let fixture = AuthorizationFixture::new("worker-directory-zero-account");
    let principal = crate::platform::resolve_current_worker_principal().unwrap();
    let setup_context = crate::platform::SetupExecutionContext::new_for_test(
        crate::platform::SetupHostPrivilege::Ordinary,
        principal.clone(),
    );
    let (plan, _layout) = super::super::current_user_worker_directory_plan_for_test(
        &setup_context,
        fixture.root.join("worker-root"),
        Some(fixture.root.clone()),
    )
    .unwrap();

    for action in &plan {
        let prepared = action.prepare().unwrap();
        assert!(prepared.effect().accounts().is_empty());
        assert!(prepared.effect().services().is_empty());
        assert!(prepared.effect().registry_keys().is_empty());
        let super::super::ActionParameters::WorkerDirectory(parameters) = prepared.parameters()
        else {
            panic!("worker-directory action lost its closed parameters")
        };
        assert_eq!(
            parameters.principal().account_policy(),
            crate::platform::WorkerAccountPolicy::CurrentUser
        );
    }
    let source = include_str!("../worker_directory.rs");
    assert!(!source.contains("resolve_named_worker_principal"));
    assert!(!source.contains("create_worker_account"));
    assert!(!source.contains("invoke_setup_authorization"));
}

#[test]
fn ordinary_user_plan_applies_and_reruns_without_authorization() {
    let fixture = AuthorizationFixture::new("ordinary-only");
    let store = ReceiptStore::new_user_for_test(fixture.user_receipt());
    let state = Arc::new(Mutex::new(Vec::new()));
    let (action, metrics) =
        Action::test_journaled_state("test.user-action", 1, Privilege::None, Arc::clone(&state));
    let mut plan = vec![action];
    let mut metadata = receipt_metadata(&[(
        "019cb047-3c00-7000-8000-000000000001",
        "2026-09-02T12:00:00Z",
    )]);
    let mut invoker = SpyInvoker::default();

    let report = execute_with_authorization(
        &mut plan,
        &store,
        &mut metadata,
        &fixture.context(),
        AuthorizationOptions::noninteractive_yes(),
        &mut invoker,
    )
    .unwrap();

    assert_eq!(report.ordinary().applied_count(), 1);
    assert_eq!(report.privileged_status(), PrivilegedStatus::NotNeeded);
    assert_eq!(invoker.calls(), 0);
    assert_eq!(metrics.mutation_calls(), 1);
    assert_eq!(*state.lock().unwrap(), vec![1]);

    let mut no_metadata = receipt_metadata(&[]);
    let second = execute_with_authorization(
        &mut plan,
        &store,
        &mut no_metadata,
        &fixture.context(),
        AuthorizationOptions::noninteractive_yes(),
        &mut invoker,
    )
    .unwrap();
    assert_eq!(second.ordinary().applied_count(), 0);
    assert_eq!(second.ordinary().recovered_count(), 0);
    assert!(second.everything_ready());
    assert_eq!(invoker.calls(), 0);
    assert_eq!(metrics.mutation_calls(), 1);
}

#[test]
fn mixed_plan_decline_applies_ordinary_prefix_and_preserves_system_delta() {
    let fixture = AuthorizationFixture::new("mixed-decline");
    let store = ReceiptStore::new_user_for_test(fixture.user_receipt());
    let state = Arc::new(Mutex::new(Vec::new()));
    let (privileged, privileged_metrics) = Action::test_journaled_state(
        "test.system-action",
        2,
        host_privilege(),
        Arc::clone(&state),
    );
    let (ordinary, ordinary_metrics) =
        Action::test_journaled_state("test.user-action", 1, Privilege::None, Arc::clone(&state));
    let mut plan = vec![privileged, ordinary];
    let mut metadata = receipt_metadata(&[
        (
            "019cb047-3c00-7000-8000-000000000001",
            "2026-09-02T12:00:00Z",
        ),
        (
            "019cb047-3c00-7000-8000-000000000002",
            "2026-09-02T12:00:01Z",
        ),
    ]);
    let mut invoker = SpyInvoker::default();

    let report = execute_with_authorization(
        &mut plan,
        &store,
        &mut metadata,
        &fixture.context(),
        AuthorizationOptions::interactive_decline(),
        &mut invoker,
    )
    .unwrap();

    assert_eq!(report.ordinary().applied_count(), 1);
    assert_eq!(
        report.privileged_status(),
        PrivilegedStatus::Pending { count: 1 }
    );
    assert_eq!(report.pending().len(), 1);
    assert_eq!(report.pending()[0].id().as_str(), "test.system-action");
    assert_eq!(
        report.pending()[0].needs_human().instructions().as_str(),
        "Authorize the displayed system change, then rerun setup.",
    );
    assert!(!report.everything_ready());
    assert_eq!(invoker.calls(), 0);
    assert_eq!(ordinary_metrics.mutation_calls(), 1);
    assert_eq!(privileged_metrics.mutation_calls(), 0);
    assert_eq!(*state.lock().unwrap(), vec![1]);
    let receipt = serde_json::from_slice::<serde_json::Value>(
        &store.read_snapshot().unwrap().to_json().unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["entries"].as_array().unwrap().len(), 2);
    assert_eq!(receipt["entries"][1]["status"], "pending");
}

#[test]
fn yes_no_elevate_and_noninteractive_default_never_invoke_authorization() {
    let cases = [
        AuthorizationOptions::noninteractive_yes(),
        AuthorizationOptions::interactive_yes_without_privilege_consent(),
        AuthorizationOptions::interactive_no_elevate(),
        AuthorizationOptions::noninteractive_default(),
    ];
    for (index, options) in cases.into_iter().enumerate() {
        let fixture = AuthorizationFixture::new(&format!("no-implicit-auth-{index}"));
        let store = ReceiptStore::new_user_for_test(fixture.user_receipt());
        let state = Arc::new(Mutex::new(Vec::new()));
        let (action, metrics) = Action::test_journaled_state(
            "test.system-action",
            1,
            host_privilege(),
            Arc::clone(&state),
        );
        let mut plan = vec![action];
        let mut metadata = receipt_metadata(&[(
            "019cb047-3c00-7000-8000-000000000001",
            "2026-09-02T12:00:00Z",
        )]);
        let mut invoker = SpyInvoker::default();

        let report = execute_with_authorization(
            &mut plan,
            &store,
            &mut metadata,
            &fixture.context(),
            options,
            &mut invoker,
        )
        .unwrap();

        assert_eq!(
            report.privileged_status(),
            PrivilegedStatus::Pending { count: 1 }
        );
        assert_eq!(report.pending().len(), 1);
        assert_eq!(report.pending()[0].id().as_str(), "test.system-action");
        assert_eq!(invoker.calls(), 0);
        assert_eq!(metrics.mutation_calls(), 0);
        assert!(state.lock().unwrap().is_empty());
        assert!(!fixture.request_path().exists());
        let receipt = serde_json::from_slice::<serde_json::Value>(
            &store.read_snapshot().unwrap().to_json().unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["entries"].as_array().unwrap().len(), 1);
        assert_eq!(receipt["entries"][0]["status"], "pending");
    }
}

#[test]
fn cancelled_authorization_keeps_deferred_actions_journaled_and_reuses_them_on_rerun() {
    let fixture = AuthorizationFixture::new("cancelled-authorization-pending");
    let store = ReceiptStore::new_user_for_test(fixture.user_receipt());
    let state = Arc::new(Mutex::new(Vec::new()));
    let (ordinary, ordinary_metrics) =
        Action::test_journaled_state("test.user-action", 1, Privilege::None, Arc::clone(&state));
    let (privileged, privileged_metrics) = Action::test_journaled_state(
        "test.system-action",
        2,
        host_privilege(),
        Arc::clone(&state),
    );
    let mut plan = vec![ordinary, privileged];
    let mut metadata = receipt_metadata(&[
        (
            "019cb047-3c00-7000-8000-000000000011",
            "2026-09-02T12:00:00Z",
        ),
        (
            "019cb047-3c00-7000-8000-000000000012",
            "2026-09-02T12:00:01Z",
        ),
    ]);
    let mut cancelled = SpyInvoker::failing();

    let error = match execute_with_authorization(
        &mut plan,
        &store,
        &mut metadata,
        &fixture.context(),
        AuthorizationOptions::interactive_accept(),
        &mut cancelled,
    ) {
        Ok(_) => panic!("cancelled authorization unexpectedly succeeded"),
        Err(error) => error,
    };

    assert_eq!(error.error_code(), "setup.elevation_required");
    assert_eq!(error.exit_code(), 13);
    assert_eq!(cancelled.calls(), 1);
    assert!(!fixture.request_path().exists());
    assert_eq!(ordinary_metrics.mutation_calls(), 1);
    assert_eq!(privileged_metrics.mutation_calls(), 0);
    assert_eq!(*state.lock().unwrap(), vec![1]);
    let first_receipt = fs::read(fixture.user_receipt()).unwrap();
    let receipt = serde_json::from_slice::<serde_json::Value>(&first_receipt).unwrap();
    assert_eq!(receipt["entries"].as_array().unwrap().len(), 2);
    assert_eq!(
        receipt["entries"][1]["entry_id"],
        "019cb047-3c00-7000-8000-000000000012"
    );
    assert_eq!(receipt["entries"][1]["status"], "pending");

    let mut no_metadata = receipt_metadata(&[]);
    let mut declined = SpyInvoker::default();
    let rerun = execute_with_authorization(
        &mut plan,
        &store,
        &mut no_metadata,
        &fixture.context(),
        AuthorizationOptions::interactive_decline(),
        &mut declined,
    )
    .unwrap();

    assert_eq!(
        rerun.privileged_status(),
        PrivilegedStatus::Pending { count: 1 }
    );
    assert_eq!(rerun.pending().len(), 1);
    assert_eq!(rerun.pending()[0].id().as_str(), "test.system-action");
    assert_eq!(fs::read(fixture.user_receipt()).unwrap(), first_receipt);
    assert_eq!(declined.calls(), 0);

    let manifest_path = fixture.manifest_path();
    let principal = crate::platform::resolve_current_worker_principal().unwrap();
    let manifest_store =
        crate::manifest::MachineManifestStore::new_user(&manifest_path, principal).unwrap();
    let mut draft = pending_manifest_draft_for_current_user();
    crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        rerun.completion(),
        &mut receipt_metadata(&[(
            "019cb047-3c00-7000-8000-000000000013",
            "2026-09-02T12:00:02Z",
        )]),
    )
    .unwrap();

    let published = manifest_store.read().unwrap().manifest;
    let pending = published.pending_actions.as_ref().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, "test.system-action");
    assert_eq!(pending[0].message, AUTHORIZATION_PENDING_INSTRUCTIONS);
}

#[test]
fn launcher_and_child_failures_keep_deferred_actions_repairable() {
    for (label, failure) in [
        ("launcher-failure", SpyInvocationFailure::Launch),
        ("child-failure", SpyInvocationFailure::Child),
    ] {
        let fixture = AuthorizationFixture::new(label);
        let store = ReceiptStore::new_user_for_test(fixture.user_receipt());
        let state = Arc::new(Mutex::new(Vec::new()));
        let (action, metrics) = Action::test_journaled_state(
            "test.system-action",
            1,
            host_privilege(),
            Arc::clone(&state),
        );
        let mut plan = vec![action];
        let mut metadata = receipt_metadata(&[(
            "019cb047-3c00-7000-8000-000000000014",
            "2026-09-02T12:00:00Z",
        )]);
        let mut failing = SpyInvoker::failing_with(failure);

        let error = match execute_with_authorization(
            &mut plan,
            &store,
            &mut metadata,
            &fixture.context(),
            AuthorizationOptions::interactive_accept(),
            &mut failing,
        ) {
            Ok(_) => panic!("authorization failure unexpectedly succeeded"),
            Err(error) => error,
        };

        assert_eq!(error.error_code(), "setup.elevation_required", "{label}");
        assert_eq!(error.exit_code(), 13, "{label}");
        assert_eq!(failing.calls(), 1, "{label}");
        assert_eq!(metrics.mutation_calls(), 0, "{label}");
        assert!(state.lock().unwrap().is_empty(), "{label}");
        assert!(!fixture.request_path().exists(), "{label}");
        let receipt_before = fs::read(fixture.user_receipt()).unwrap();
        let receipt = serde_json::from_slice::<serde_json::Value>(&receipt_before).unwrap();
        assert_eq!(receipt["entries"].as_array().unwrap().len(), 1, "{label}");
        assert_eq!(receipt["entries"][0]["status"], "pending", "{label}");

        let mut no_metadata = receipt_metadata(&[]);
        let mut declined = SpyInvoker::default();
        let repair = execute_with_authorization(
            &mut plan,
            &store,
            &mut no_metadata,
            &fixture.context(),
            AuthorizationOptions::interactive_decline(),
            &mut declined,
        )
        .unwrap();
        assert_eq!(fs::read(fixture.user_receipt()).unwrap(), receipt_before);
        assert_eq!(repair.pending().len(), 1);

        let manifest_path = fixture.manifest_path();
        let principal = crate::platform::resolve_current_worker_principal().unwrap();
        let manifest_store =
            crate::manifest::MachineManifestStore::new_user(&manifest_path, principal).unwrap();
        let mut draft = pending_manifest_draft_for_current_user();
        crate::setup::pending::publish_manifest(
            &manifest_store,
            &store,
            &mut draft,
            repair.completion(),
            &mut receipt_metadata(&[(
                "019cb047-3c00-7000-8000-000000000015",
                "2026-09-02T12:00:01Z",
            )]),
        )
        .unwrap();
        let pending = manifest_store
            .read()
            .unwrap()
            .manifest
            .pending_actions
            .unwrap();
        assert_eq!(pending.len(), 1, "{label}");
        assert_eq!(pending[0].id, "test.system-action", "{label}");
    }
}

#[test]
fn explicit_interactive_or_noninteractive_consent_invokes_exactly_once() {
    for (index, options) in [
        AuthorizationOptions::interactive_accept(),
        AuthorizationOptions::noninteractive_authorize_system(),
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = AuthorizationFixture::new(&format!("explicit-auth-{index}"));
        let store = ReceiptStore::new_user_for_test(fixture.user_receipt());
        let state = Arc::new(Mutex::new(Vec::new()));
        let (action, metrics) = Action::test_journaled_state(
            "test.system-action",
            1,
            host_privilege(),
            Arc::clone(&state),
        );
        let mut plan = vec![action];
        let mut metadata = receipt_metadata(&[(
            "019cb047-3c00-7000-8000-000000000001",
            "2026-09-02T12:00:00Z",
        )]);
        let mut invoker = SpyInvoker::default();

        let report = execute_with_authorization(
            &mut plan,
            &store,
            &mut metadata,
            &fixture.context(),
            options,
            &mut invoker,
        )
        .unwrap();

        assert_eq!(
            report.privileged_status(),
            PrivilegedStatus::AuthorizationLaunched { count: 1 }
        );
        assert_eq!(report.pending().len(), 1);
        assert_eq!(report.pending()[0].id().as_str(), "test.system-action");
        assert_eq!(
            report.pending()[0].needs_human().instructions().as_str(),
            AUTHORIZATION_PENDING_INSTRUCTIONS
        );
        assert!(!report.everything_ready());
        assert_eq!(invoker.calls(), 1);
        assert_eq!(
            metrics.mutation_calls(),
            0,
            "parent process must not dispatch system actions"
        );
        assert!(state.lock().unwrap().is_empty());
        assert_eq!(invoker.executable(), Some(fixture.context().executable()));
        assert_eq!(invoker.request_path(), Some(fixture.request_path()));
        assert!(invoker.request_digest().is_some_and(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        }));
        let receipt = serde_json::from_slice::<serde_json::Value>(
            &store.read_snapshot().unwrap().to_json().unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["entries"][0]["status"], "pending");
    }
}

#[test]
fn authorized_completion_projects_the_complete_pending_set_for_both_grant_policies() {
    for (label, options) in [
        (
            "interactive",
            AuthorizationOptions::from_policy(SystemAuthorizationPolicy::InteractiveConsent, false)
                .unwrap(),
        ),
        (
            "explicit-noninteractive",
            AuthorizationOptions::from_policy(
                SystemAuthorizationPolicy::ExplicitNoninteractive,
                false,
            )
            .unwrap(),
        ),
    ] {
        assert_complete_pending_projection(
            label,
            options,
            PrivilegedStatus::AuthorizationLaunched { count: 1 },
            1,
        );
    }
}

#[test]
fn declined_authorization_projects_the_complete_pending_set_without_invocation() {
    assert_complete_pending_projection(
        "declined",
        AuthorizationOptions::from_policy(SystemAuthorizationPolicy::NotGranted, false).unwrap(),
        PrivilegedStatus::Pending { count: 1 },
        0,
    );
}

#[test]
fn authorization_completion_rejects_invalid_display_order_before_pending_append() {
    let fixture = AuthorizationFixture::new("invalid-completion-order");
    let store = ReceiptStore::new_user_for_test(fixture.user_receipt());
    let ordinary = super::super::execution::apply_plan_with_journal(
        &mut [],
        &store,
        &mut receipt_metadata(&[]),
    )
    .unwrap();
    let state = Arc::new(Mutex::new(Vec::new()));
    let privileged =
        Action::test_journaled_state("test.system-action", 1, host_privilege(), state).0;
    let pending = vec![deferred_authorization_pending(&privileged)];
    let error = match super::super::execution::complete_authorized_execution(
        ordinary,
        pending,
        &[],
        &store,
        &mut receipt_metadata(&[(
            "019cb047-3c00-7000-8000-000000000040",
            "2026-09-02T12:00:00Z",
        )]),
    ) {
        Ok(_) => panic!("invalid display order unexpectedly produced a completion token"),
        Err(error) => error,
    };

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code(), 13);
    assert!(!fixture.user_receipt().exists());
}

#[test]
fn ordinary_only_token_is_stale_after_authorization_reissues_completion() {
    let fixture = AuthorizationFixture::new("stale-ordinary-token");
    let store = ReceiptStore::new_user_for_test(fixture.user_receipt());
    let stale_ordinary = super::super::execution::apply_plan_with_journal(
        &mut [],
        &store,
        &mut receipt_metadata(&[]),
    )
    .unwrap();
    let ordinary_to_consume = super::super::execution::apply_plan_with_journal(
        &mut [],
        &store,
        &mut receipt_metadata(&[]),
    )
    .unwrap();
    let state = Arc::new(Mutex::new(Vec::new()));
    let privileged =
        Action::test_journaled_state("test.system-action", 1, host_privilege(), state).0;
    let displayed_order = vec![privileged.name().clone()];
    let pending = vec![deferred_authorization_pending(&privileged)];
    let (_, replacement) = super::super::execution::complete_authorized_execution(
        ordinary_to_consume,
        pending,
        &displayed_order,
        &store,
        &mut receipt_metadata(&[(
            "019cb047-3c00-7000-8000-000000000041",
            "2026-09-02T12:00:00Z",
        )]),
    )
    .unwrap();

    let manifest_path = fixture.manifest_path();
    let principal = crate::platform::resolve_current_worker_principal().unwrap();
    let manifest_store =
        crate::manifest::MachineManifestStore::new_user(&manifest_path, principal).unwrap();
    let mut draft = pending_manifest_draft_for_current_user();
    let receipt_before = fs::read(fixture.user_receipt()).unwrap();
    let error = crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        stale_ordinary.completion(),
        &mut receipt_metadata(&[]),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        crate::setup::pending::PendingError::Receipt(ReceiptStoreError::IntentConflict)
    ));
    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code().as_i32(), 13);
    assert!(draft.pending_actions.is_none());
    assert!(!manifest_path.exists());
    assert_eq!(fs::read(fixture.user_receipt()).unwrap(), receipt_before);

    crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        &replacement,
        &mut receipt_metadata(&[(
            "019cb047-3c00-7000-8000-000000000042",
            "2026-09-02T12:00:01Z",
        )]),
    )
    .unwrap();
    assert_eq!(
        manifest_store
            .read()
            .unwrap()
            .manifest
            .pending_actions
            .unwrap()[0]
            .id,
        "test.system-action"
    );
}

#[test]
fn verified_reprobe_omits_only_the_resolved_privileged_occurrence() {
    let fixture = AuthorizationFixture::new("verified-reprobe-resolution");
    let store = ReceiptStore::new_user_for_test(fixture.user_receipt());
    let state = Arc::new(Mutex::new(Vec::new()));
    let first = Action::test_journaled_state(
        "test.first-system-action",
        1,
        host_privilege(),
        Arc::clone(&state),
    )
    .0;
    let second = Action::test_journaled_state(
        "test.second-system-action",
        2,
        host_privilege(),
        Arc::clone(&state),
    )
    .0;
    let mut plan = vec![first, second];
    let mut invoker = SpyInvoker::default();
    let first_report = execute_with_authorization(
        &mut plan,
        &store,
        &mut receipt_metadata(&[
            (
                "019cb047-3c00-7000-8000-000000000051",
                "2026-09-02T12:00:00Z",
            ),
            (
                "019cb047-3c00-7000-8000-000000000052",
                "2026-09-02T12:00:01Z",
            ),
        ]),
        &fixture.context(),
        AuthorizationOptions::interactive_decline(),
        &mut invoker,
    )
    .unwrap();
    assert_eq!(first_report.pending().len(), 2);
    assert_eq!(invoker.calls(), 0);

    let manifest_path = fixture.manifest_path();
    let principal = crate::platform::resolve_current_worker_principal().unwrap();
    let manifest_store =
        crate::manifest::MachineManifestStore::new_user(&manifest_path, principal).unwrap();
    let mut draft = pending_manifest_draft_for_current_user();
    crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        first_report.completion(),
        &mut receipt_metadata(&[(
            "019cb047-3c00-7000-8000-000000000053",
            "2026-09-02T12:00:02Z",
        )]),
    )
    .unwrap();

    state.lock().unwrap().push(1);
    let resolved = execute_with_authorization(
        &mut plan,
        &store,
        &mut receipt_metadata(&[]),
        &fixture.context(),
        AuthorizationOptions::interactive_decline(),
        &mut invoker,
    )
    .unwrap();
    assert_eq!(
        resolved
            .pending()
            .iter()
            .map(|pending| pending.id().as_str())
            .collect::<Vec<_>>(),
        ["test.second-system-action"]
    );
    assert_eq!(
        resolved.privileged_status(),
        PrivilegedStatus::Pending { count: 1 }
    );
    crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        resolved.completion(),
        &mut receipt_metadata(&[(
            "019cb047-3c00-7000-8000-000000000054",
            "2026-09-02T12:00:03Z",
        )]),
    )
    .unwrap();
    assert_eq!(
        manifest_store
            .read()
            .unwrap()
            .manifest
            .pending_actions
            .unwrap()
            .iter()
            .map(|pending| pending.id.as_str())
            .collect::<Vec<_>>(),
        ["test.second-system-action"]
    );

    state.lock().unwrap().clear();
    let recurring = execute_with_authorization(
        &mut plan,
        &store,
        &mut receipt_metadata(&[(
            "019cb047-3c00-7000-8000-000000000055",
            "2026-09-02T12:00:04Z",
        )]),
        &fixture.context(),
        AuthorizationOptions::interactive_decline(),
        &mut invoker,
    )
    .unwrap();
    assert_eq!(
        recurring
            .pending()
            .iter()
            .map(|pending| pending.id().as_str())
            .collect::<Vec<_>>(),
        ["test.first-system-action", "test.second-system-action"]
    );
    crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        recurring.completion(),
        &mut receipt_metadata(&[(
            "019cb047-3c00-7000-8000-000000000056",
            "2026-09-02T12:00:05Z",
        )]),
    )
    .unwrap();

    let receipt = serde_json::from_slice::<serde_json::Value>(
        &store.read_snapshot().unwrap().to_json().unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["entries"].as_array().unwrap().len(), 3);
    assert!(receipt["entries"]
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| entry["status"] == "pending"));
    assert_eq!(
        receipt["entries"][2]["entry_id"],
        "019cb047-3c00-7000-8000-000000000055"
    );
    assert_eq!(
        receipt["pending_publications"][1]["pending"],
        serde_json::json!([{
            "action_id": "test.second-system-action",
            "entry_id": "019cb047-3c00-7000-8000-000000000052"
        }])
    );
    assert_eq!(
        receipt["pending_publications"][2]["pending"],
        serde_json::json!([
            {
                "action_id": "test.first-system-action",
                "entry_id": "019cb047-3c00-7000-8000-000000000055"
            },
            {
                "action_id": "test.second-system-action",
                "entry_id": "019cb047-3c00-7000-8000-000000000052"
            }
        ])
    );
}

#[test]
fn already_converged_privileged_actions_do_not_prompt_or_become_pending() {
    let fixture = AuthorizationFixture::new("privileged-already-done");
    let store = ReceiptStore::new_user_for_test(fixture.user_receipt());
    let state = Arc::new(Mutex::new(vec![1]));
    let (action, metrics) = Action::test_journaled_state(
        "test.system-action",
        1,
        host_privilege(),
        Arc::clone(&state),
    );
    let mut plan = vec![action];
    let mut metadata = receipt_metadata(&[]);
    let mut invoker = SpyInvoker::default();

    let report = execute_with_authorization(
        &mut plan,
        &store,
        &mut metadata,
        &fixture.context(),
        AuthorizationOptions::interactive_accept(),
        &mut invoker,
    )
    .unwrap();

    assert_eq!(report.privileged_status(), PrivilegedStatus::NotNeeded);
    assert!(report.everything_ready());
    assert_eq!(invoker.calls(), 0);
    assert_eq!(metrics.mutation_calls(), 0);
    assert!(!fixture.request_path().exists());
}

#[test]
fn privileged_needs_human_is_journaled_and_exposed_without_prompt() {
    let fixture = AuthorizationFixture::new("privileged-needs-human");
    let store = ReceiptStore::new_user_for_test(fixture.user_receipt());
    let state = Arc::new(Mutex::new(Vec::new()));
    let (action, metrics) = Action::test_named_needs_human(
        "test.needs-human",
        host_privilege(),
        Arc::clone(&state),
        NeedsHuman::new(
            HumanInstructions::new("Approve the operating-system setting.").unwrap(),
            None,
        ),
    );
    let mut plan = vec![action];
    let mut metadata = receipt_metadata(&[(
        "019cb047-3c00-7000-8000-000000000001",
        "2026-09-02T12:00:00Z",
    )]);
    let mut invoker = SpyInvoker::default();

    let report = execute_with_authorization(
        &mut plan,
        &store,
        &mut metadata,
        &fixture.context(),
        AuthorizationOptions::interactive_accept(),
        &mut invoker,
    )
    .unwrap();

    assert_eq!(
        report.privileged_status(),
        PrivilegedStatus::NeedsHuman { count: 1 }
    );
    assert_eq!(report.pending().len(), 1);
    assert_eq!(report.pending()[0].id().as_str(), "test.needs-human");
    assert_eq!(report.pending()[0].severity(), PendingSeverity::Warning);
    assert_eq!(
        report.pending()[0].needs_human().instructions().as_str(),
        "Approve the operating-system setting."
    );
    assert!(!report.everything_ready());
    assert_eq!(invoker.calls(), 0);
    assert_eq!(metrics.mutation_calls(), 0);
    let receipt = serde_json::from_slice::<serde_json::Value>(
        &store.read_snapshot().unwrap().to_json().unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["entries"].as_array().unwrap().len(), 1);
    assert_eq!(
        receipt["entries"][0]["action"]["parameters"]["action_id"],
        "test.needs-human"
    );
    assert_eq!(receipt["entries"][0]["status"], "pending");
    assert_eq!(receipt["entries"][0]["privilege_used"], "none");
    for field in [
        "files_created",
        "files_modified",
        "services",
        "accounts",
        "registry_keys",
        "firewall_rules",
    ] {
        assert!(receipt["entries"][0][field].as_array().unwrap().is_empty());
    }
    assert!(receipt["entries"][0]["download_provenance"].is_null());

    let first_receipt = fs::read(fixture.user_receipt()).unwrap();
    let mut no_metadata = receipt_metadata(&[]);
    let rerun = execute_with_authorization(
        &mut plan,
        &store,
        &mut no_metadata,
        &fixture.context(),
        AuthorizationOptions::interactive_accept(),
        &mut invoker,
    )
    .unwrap();
    assert_eq!(rerun.pending(), report.pending());
    assert_eq!(fs::read(fixture.user_receipt()).unwrap(), first_receipt);
    assert_eq!(invoker.calls(), 0);
}

#[test]
fn mixed_needs_human_report_preserves_the_displayed_plan_order() {
    let fixture = AuthorizationFixture::new("mixed-needs-human-order");
    let store = ReceiptStore::new_user_for_test(fixture.user_receipt());
    let state = Arc::new(Mutex::new(Vec::new()));
    let (system, _) = Action::test_named_needs_human(
        "test.system-approval",
        host_privilege(),
        Arc::clone(&state),
        NeedsHuman::new(
            HumanInstructions::new("Approve the system setting.").unwrap(),
            None,
        ),
    );
    let (user, _) = Action::test_named_needs_human(
        "test.user-approval",
        Privilege::None,
        Arc::clone(&state),
        NeedsHuman::new(
            HumanInstructions::new("Approve the user setting.").unwrap(),
            None,
        ),
    );
    let mut plan = vec![system, user];
    let mut metadata = receipt_metadata(&[
        (
            "019cb047-3c00-7000-8000-000000000001",
            "2026-09-02T12:00:00Z",
        ),
        (
            "019cb047-3c00-7000-8000-000000000002",
            "2026-09-02T12:00:01Z",
        ),
    ]);
    let mut invoker = SpyInvoker::default();

    let report = execute_with_authorization(
        &mut plan,
        &store,
        &mut metadata,
        &fixture.context(),
        AuthorizationOptions::interactive_decline(),
        &mut invoker,
    )
    .unwrap();

    assert_eq!(
        report
            .pending()
            .iter()
            .map(|pending| pending.id().as_str())
            .collect::<Vec<_>>(),
        ["test.system-approval", "test.user-approval"]
    );
    assert_eq!(invoker.calls(), 0);
    assert!(state.lock().unwrap().is_empty());
}

#[test]
fn privileged_pending_metadata_exhaustion_keeps_a_valid_prefix_and_repairs_on_rerun() {
    let fixture = AuthorizationFixture::new("privileged-pending-metadata-exhaustion");
    let store = ReceiptStore::new_user_for_test(fixture.user_receipt());
    let state = Arc::new(Mutex::new(Vec::new()));
    let make_action = |name, instruction| {
        Action::test_named_needs_human(
            name,
            host_privilege(),
            Arc::clone(&state),
            NeedsHuman::new(HumanInstructions::new(instruction).unwrap(), None),
        )
        .0
    };
    let mut plan = vec![
        make_action(
            "test.first-system-approval",
            "Approve the first system setting.",
        ),
        make_action(
            "test.second-system-approval",
            "Approve the second system setting.",
        ),
    ];
    let mut one_metadata = receipt_metadata(&[(
        "019cb047-3c00-7000-8000-000000000001",
        "2026-09-02T12:00:00Z",
    )]);
    let mut invoker = SpyInvoker::default();

    let error = match execute_with_authorization(
        &mut plan,
        &store,
        &mut one_metadata,
        &fixture.context(),
        AuthorizationOptions::interactive_accept(),
        &mut invoker,
    ) {
        Ok(_) => panic!("metadata exhaustion unexpectedly completed setup"),
        Err(error) => error,
    };

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code(), 13);
    assert_eq!(invoker.calls(), 0);
    assert!(!fixture.request_path().exists());
    assert!(state.lock().unwrap().is_empty());
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 1);

    let mut repair_metadata = receipt_metadata(&[(
        "019cb047-3c00-7000-8000-000000000002",
        "2026-09-02T12:00:01Z",
    )]);
    let repaired = execute_with_authorization(
        &mut plan,
        &store,
        &mut repair_metadata,
        &fixture.context(),
        AuthorizationOptions::interactive_accept(),
        &mut invoker,
    )
    .unwrap();

    assert_eq!(repaired.pending().len(), 2);
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 2);
    assert_eq!(invoker.calls(), 0);
    assert!(state.lock().unwrap().is_empty());
}

#[test]
fn privileged_pending_receipt_publication_failure_exposes_no_partial_document_or_prompt() {
    let fixture = AuthorizationFixture::new("privileged-pending-publication-failure");
    let store = ReceiptStore::new_user_for_test_failing_before_replace(fixture.user_receipt());
    let state = Arc::new(Mutex::new(Vec::new()));
    let (action, metrics) = Action::test_named_needs_human(
        "test.system-approval",
        host_privilege(),
        Arc::clone(&state),
        NeedsHuman::new(
            HumanInstructions::new("Approve the system setting.").unwrap(),
            None,
        ),
    );
    let mut plan = vec![action];
    let mut metadata = receipt_metadata(&[(
        "019cb047-3c00-7000-8000-000000000001",
        "2026-09-02T12:00:00Z",
    )]);
    let mut invoker = SpyInvoker::default();

    let error = match execute_with_authorization(
        &mut plan,
        &store,
        &mut metadata,
        &fixture.context(),
        AuthorizationOptions::interactive_accept(),
        &mut invoker,
    ) {
        Ok(_) => panic!("interrupted receipt publication unexpectedly completed setup"),
        Err(error) => error,
    };

    assert_eq!(error.error_code(), "setup.receipt_conflict");
    assert_eq!(error.exit_code(), 13);
    assert_eq!(invoker.calls(), 0);
    assert_eq!(metrics.mutation_calls(), 0);
    assert!(state.lock().unwrap().is_empty());
    assert!(!fixture.request_path().exists());
    assert!(!fixture.user_receipt().exists());
}

#[test]
fn privileged_check_failure_restores_original_plan_after_ordinary_progress() {
    let fixture = AuthorizationFixture::new("restore-plan-on-check-error");
    let store = ReceiptStore::new_user_for_test(fixture.user_receipt());
    let state = Arc::new(Mutex::new(Vec::new()));
    let (privileged, _) = Action::test_check_failure(host_privilege(), Arc::clone(&state));
    let (ordinary, ordinary_metrics) =
        Action::test_journaled_state("test.user-action", 1, Privilege::None, Arc::clone(&state));
    let mut plan = vec![privileged, ordinary];
    let mut metadata = receipt_metadata(&[(
        "019cb047-3c00-7000-8000-000000000001",
        "2026-09-02T12:00:00Z",
    )]);
    let mut invoker = SpyInvoker::default();

    assert!(execute_with_authorization(
        &mut plan,
        &store,
        &mut metadata,
        &fixture.context(),
        AuthorizationOptions::interactive_decline(),
        &mut invoker,
    )
    .is_err());

    assert_eq!(ordinary_metrics.mutation_calls(), 1);
    assert_eq!(*state.lock().unwrap(), vec![1]);
    assert_eq!(
        plan.iter()
            .map(|action| action.name().as_str())
            .collect::<Vec<_>>(),
        vec!["test.state", "test.user-action"]
    );
}

#[test]
fn privileged_runner_accepts_an_exact_subset_once_and_journals_real_actions() {
    let fixture = AuthorizationFixture::new("runner-subset-once");
    let state = Arc::new(Mutex::new(Vec::new()));
    let displayed = vec![
        Action::test_journaled_state(
            "test.first-system-action",
            1,
            host_privilege(),
            Arc::clone(&state),
        )
        .0,
        Action::test_journaled_state(
            "test.converged-system-action",
            2,
            host_privilege(),
            Arc::clone(&state),
        )
        .0,
    ];
    let context = fixture.context();
    let digest = write_request(&displayed, &context).unwrap();
    let retained_request = fs::read(fixture.request_path()).unwrap();
    let (recomputed, metrics) = Action::test_journaled_state(
        "test.first-system-action",
        1,
        host_privilege(),
        Arc::clone(&state),
    );
    let mut recomputed = vec![recomputed];
    let store = ReceiptStore::new_for_test(fixture.system_receipt());
    let mut metadata = receipt_metadata(&[(
        "019cb047-3c00-7000-8000-000000000011",
        "2026-09-02T12:00:01Z",
    )]);

    let report =
        run_privileged_request(&context, &digest, &mut recomputed, &store, &mut metadata).unwrap();

    assert_eq!(report.applied_count(), 1);
    assert_eq!(metrics.mutation_calls(), 1);
    assert_eq!(*state.lock().unwrap(), vec![1]);
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 1);
    assert!(!fixture.request_path().exists());

    let (replayed, replay_metrics) = Action::test_journaled_state(
        "test.first-system-action",
        1,
        host_privilege(),
        Arc::clone(&state),
    );
    let mut replayed = vec![replayed];
    let mut no_metadata = receipt_metadata(&[]);
    let error = run_privileged_request(&context, &digest, &mut replayed, &store, &mut no_metadata)
        .unwrap_err();
    assert_eq!(error.error_code(), "setup.plan_invalid");
    assert_eq!(error.exit_code(), 13);
    assert_eq!(replay_metrics.mutation_calls(), 0);
    assert_eq!(*state.lock().unwrap(), vec![1]);

    fs::write(fixture.request_path(), retained_request).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(fixture.request_path(), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (restored, restored_metrics) = Action::test_journaled_state(
        "test.first-system-action",
        1,
        host_privilege(),
        Arc::clone(&state),
    );
    let mut restored = vec![restored];
    let mut no_metadata = receipt_metadata(&[]);
    let error = run_privileged_request(&context, &digest, &mut restored, &store, &mut no_metadata)
        .unwrap_err();
    assert_eq!(error.error_code(), "setup.plan_invalid");
    assert_eq!(restored_metrics.mutation_calls(), 0);
    assert_eq!(*state.lock().unwrap(), vec![1]);
}

#[test]
fn system_execution_seam_routes_user_and_host_actions_once() {
    let fixture = AuthorizationFixture::new("elevated-split-execution");
    let principal = crate::platform::resolve_current_worker_principal().unwrap();
    let context =
        crate::platform::SetupExecutionContext::new_for_test(host_setup_privilege(), principal);
    let store = ReceiptStore::new_for_test(fixture.system_receipt());
    let state = Arc::new(Mutex::new(Vec::new()));
    let (ordinary, ordinary_metrics) =
        Action::test_journaled_state("test.user-action", 1, Privilege::None, Arc::clone(&state));
    let (privileged, privileged_metrics) = Action::test_journaled_state(
        "test.system-action",
        2,
        host_privilege(),
        Arc::clone(&state),
    );
    let mut plan = vec![ordinary, privileged];
    let mut metadata = receipt_metadata(&[
        (
            "019cb047-3c00-7000-8000-000000000021",
            "2026-09-02T12:00:01Z",
        ),
        (
            "019cb047-3c00-7000-8000-000000000022",
            "2026-09-02T12:00:02Z",
        ),
    ]);
    let mut user_runner = SpyPreparedRunner::new(Privilege::None);

    let report = execute_system_plan_with_test_user_runner(
        &mut plan,
        &store,
        &mut metadata,
        &context,
        &mut user_runner,
    )
    .unwrap();

    assert_eq!(report.applied_count(), 2);
    assert_eq!(user_runner.calls, 1);
    assert_eq!(ordinary_metrics.mutation_calls(), 1);
    assert_eq!(privileged_metrics.mutation_calls(), 1);
    assert_eq!(*state.lock().unwrap(), vec![1, 2]);
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 2);

    let mut no_metadata = receipt_metadata(&[]);
    let second = execute_system_plan_with_test_user_runner(
        &mut plan,
        &store,
        &mut no_metadata,
        &context,
        &mut user_runner,
    )
    .unwrap();
    assert!(second.is_nothing_to_do());
    assert_eq!(user_runner.calls, 1);
}

#[test]
fn elevated_system_execution_rejects_scope_identity_and_privilege_before_mutation() {
    for case in ["user-store", "different-worker", "ordinary-host"] {
        let fixture = AuthorizationFixture::new(&format!("elevated-preflight-{case}"));
        let current = crate::platform::resolve_current_worker_principal().unwrap();
        let context = match case {
            "different-worker" => crate::platform::SetupExecutionContext::new_for_test(
                host_setup_privilege(),
                current,
            )
            .with_original_principal_for_test(different_principal()),
            "ordinary-host" => crate::platform::SetupExecutionContext::new_for_test(
                crate::platform::SetupHostPrivilege::Ordinary,
                current,
            ),
            _ => crate::platform::SetupExecutionContext::new_for_test(
                host_setup_privilege(),
                current,
            ),
        };
        let store = if case == "user-store" {
            ReceiptStore::new_user_for_test(fixture.user_receipt())
        } else {
            ReceiptStore::new_for_test(fixture.system_receipt())
        };
        let state = Arc::new(Mutex::new(Vec::new()));
        let (action, metrics) = Action::test_journaled_state(
            "test.system-action",
            1,
            host_privilege(),
            Arc::clone(&state),
        );
        let mut plan = vec![action];
        let mut metadata = receipt_metadata(&[]);
        let mut user_runner = SpyPreparedRunner::new(Privilege::None);

        let error = execute_system_plan_with_test_user_runner(
            &mut plan,
            &store,
            &mut metadata,
            &context,
            &mut user_runner,
        )
        .unwrap_err();

        assert_eq!(error.exit_code(), 13, "{case}");
        assert_eq!(metrics.mutation_calls(), 0, "{case}");
        assert_eq!(user_runner.calls, 0, "{case}");
        assert!(state.lock().unwrap().is_empty(), "{case}");
        assert!(!fixture.user_receipt().exists(), "{case}");
        assert!(!fixture.system_receipt().exists(), "{case}");
    }
}

#[test]
fn prepared_user_action_failure_retries_only_through_the_user_runner() {
    let fixture = AuthorizationFixture::new("user-runner-retry");
    let principal = crate::platform::resolve_current_worker_principal().unwrap();
    let context =
        crate::platform::SetupExecutionContext::new_for_test(host_setup_privilege(), principal);
    let store = ReceiptStore::new_for_test(fixture.system_receipt());
    let state = Arc::new(Mutex::new(Vec::new()));
    let (action, metrics) =
        Action::test_journaled_state("test.user-action", 1, Privilege::None, Arc::clone(&state));
    let mut plan = vec![action];
    let mut metadata = receipt_metadata(&[(
        "019cb047-3c00-7000-8000-000000000023",
        "2026-09-02T12:00:03Z",
    )]);
    let mut runner = FailOncePreparedRunner::default();

    let error = execute_system_plan_with_test_user_runner(
        &mut plan,
        &store,
        &mut metadata,
        &context,
        &mut runner,
    )
    .unwrap_err();
    assert_eq!(error.error_code(), "setup.apply_failed");
    assert_eq!(runner.calls, 1);
    assert_eq!(metrics.mutation_calls(), 0);
    assert!(state.lock().unwrap().is_empty());
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 0);

    let mut no_metadata = receipt_metadata(&[]);
    let report = execute_system_plan_with_test_user_runner(
        &mut plan,
        &store,
        &mut no_metadata,
        &context,
        &mut runner,
    )
    .unwrap();
    assert_eq!(report.applied_count(), 1);
    assert_eq!(runner.calls, 2);
    assert_eq!(metrics.mutation_calls(), 1);
    assert_eq!(*state.lock().unwrap(), vec![1]);
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 1);
}

#[test]
fn privileged_runner_rejects_a_self_consistent_request_replacement_not_bound_to_consent() {
    let fixture = AuthorizationFixture::new("request-digest-replacement");
    let context = fixture.context();
    let state = Arc::new(Mutex::new(Vec::new()));
    let displayed = vec![
        Action::test_journaled_state(
            "test.original-system-action",
            1,
            host_privilege(),
            Arc::clone(&state),
        )
        .0,
    ];
    let approved_digest = write_request(&displayed, &context).unwrap();
    fs::remove_file(fixture.request_path()).unwrap();
    let replacement = vec![
        Action::test_journaled_state(
            "test.replacement-system-action",
            2,
            host_privilege(),
            Arc::clone(&state),
        )
        .0,
    ];
    let replacement_digest = write_request(&replacement, &context).unwrap();
    assert_ne!(approved_digest, replacement_digest);
    let (action, metrics) = Action::test_journaled_state(
        "test.replacement-system-action",
        2,
        host_privilege(),
        Arc::clone(&state),
    );
    let mut plan = vec![action];
    let store = ReceiptStore::new_for_test(fixture.system_receipt());
    let mut metadata = receipt_metadata(&[]);

    let error =
        run_privileged_request(&context, &approved_digest, &mut plan, &store, &mut metadata)
            .unwrap_err();

    assert_eq!(error.error_code(), "setup.plan_invalid");
    assert_eq!(metrics.mutation_calls(), 0);
    assert!(state.lock().unwrap().is_empty());
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 0);
}

#[test]
fn request_wire_rejects_version_size_expiry_unknown_fields_and_secret_values() {
    for case in [
        "version",
        "oversized",
        "expired",
        "unknown",
        "scope",
        "secret",
        "truncated",
    ] {
        let fixture = AuthorizationFixture::new(&format!("wire-{case}"));
        let state = Arc::new(Mutex::new(Vec::new()));
        let displayed = vec![
            Action::test_journaled_state(
                "test.system-action",
                1,
                host_privilege(),
                Arc::clone(&state),
            )
            .0,
        ];
        let context = fixture.context();
        let digest = write_request(&displayed, &context).unwrap();
        let mut value =
            serde_json::from_slice::<serde_json::Value>(&fs::read(fixture.request_path()).unwrap())
                .unwrap();
        let runner_context = match case {
            "version" => {
                value["schema_version"] = serde_json::json!(2);
                context.clone()
            }
            "oversized" => {
                value["padding"] = serde_json::json!("x".repeat(MAX_REQUEST_BYTES + 1));
                context.clone()
            }
            "expired" => fixture.context_at("2026-09-02T12:05:00Z"),
            "unknown" => {
                value["displayed_actions"][0]["argv"] = serde_json::json!(["sh", "-c"]);
                context.clone()
            }
            "scope" => {
                value["installation_scope"] = serde_json::json!("user");
                context.clone()
            }
            "secret" => {
                value["executable"] = serde_json::json!("/usr/bin/api_key=do-not-echo");
                context.clone()
            }
            "truncated" => context.clone(),
            _ => unreachable!(),
        };
        if case == "truncated" {
            fs::write(fixture.request_path(), b"{").unwrap();
        } else if case != "expired" {
            fs::write(fixture.request_path(), serde_json::to_vec(&value).unwrap()).unwrap();
        }
        let (action, metrics) = Action::test_journaled_state(
            "test.system-action",
            1,
            host_privilege(),
            Arc::clone(&state),
        );
        let mut plan = vec![action];
        let store = ReceiptStore::new_for_test(fixture.system_receipt());
        let mut metadata = receipt_metadata(&[]);

        let error =
            run_privileged_request(&runner_context, &digest, &mut plan, &store, &mut metadata)
                .unwrap_err();

        assert_eq!(error.error_code(), "setup.plan_invalid", "{case}");
        assert_eq!(error.exit_code(), 13, "{case}");
        assert!(!error.to_string().contains("do-not-echo"), "{case}");
        assert_eq!(metrics.mutation_calls(), 0, "{case}");
        assert!(state.lock().unwrap().is_empty(), "{case}");
        assert_eq!(store.read_snapshot().unwrap().entry_count(), 0, "{case}");
    }
}

#[test]
fn generated_request_is_size_bounded_before_private_file_creation() {
    let fixture = AuthorizationFixture::new("generated-oversized");
    let state = Arc::new(Mutex::new(Vec::new()));
    let huge_name = format!("test.{}", "a".repeat(MAX_REQUEST_BYTES));
    let (action, metrics) =
        Action::test_journaled_state(&huge_name, 1, host_privilege(), Arc::clone(&state));
    let mut plan = vec![action];
    let store = ReceiptStore::new_user_for_test(fixture.user_receipt());
    let mut metadata = receipt_metadata(&[]);
    let mut invoker = SpyInvoker::default();

    let result = execute_with_authorization(
        &mut plan,
        &store,
        &mut metadata,
        &fixture.context(),
        AuthorizationOptions::interactive_accept(),
        &mut invoker,
    );
    let error = match result {
        Ok(_) => panic!("oversized request unexpectedly reached authorization"),
        Err(error) => error,
    };

    assert_eq!(error.error_code(), "setup.plan_invalid");
    assert_eq!(error.exit_code(), 13);
    assert_eq!(invoker.calls(), 0);
    assert_eq!(metrics.mutation_calls(), 0);
    assert!(state.lock().unwrap().is_empty());
    assert!(!fixture.request_path().exists());
    assert!(!fixture.user_receipt().exists());
}

#[test]
fn generated_request_rejects_secret_shaped_principal_before_file_creation() {
    let fixture = AuthorizationFixture::new("generated-secret-principal");
    let state = Arc::new(Mutex::new(Vec::new()));
    let displayed = vec![
        Action::test_journaled_state(
            "test.system-action",
            1,
            host_privilege(),
            Arc::clone(&state),
        )
        .0,
    ];
    let mut context = fixture.context();
    context.principal = crate::platform::WorkerPrincipal::new(
        context.principal.principal_kind(),
        context.principal.principal_id(),
        "api_key=do-not-write",
        context.principal.account_policy(),
    )
    .unwrap();

    let error = write_request(&displayed, &context).unwrap_err();

    assert_eq!(error.error_code(), "setup.plan_invalid");
    assert!(!error.to_string().contains("do-not-write"));
    assert!(!fixture.request_path().exists());
}

#[test]
fn authorization_request_binds_worker_account_policy() {
    let fixture = AuthorizationFixture::new("account-policy-binding");
    let state = Arc::new(Mutex::new(Vec::new()));
    let displayed = vec![
        Action::test_journaled_state(
            "test.system-action",
            1,
            host_privilege(),
            Arc::clone(&state),
        )
        .0,
    ];
    let context = fixture.context();
    write_request(&displayed, &context).unwrap();
    let mut value =
        serde_json::from_slice::<serde_json::Value>(&fs::read(fixture.request_path()).unwrap())
            .unwrap();
    assert_eq!(
        value["principal"]["account_policy"],
        serde_json::json!("current-user")
    );
    value["principal"]["account_policy"] = serde_json::json!("dedicated");
    let altered = serde_json::to_vec(&value).unwrap();
    let altered_digest = request_digest(&altered);
    fs::write(fixture.request_path(), altered).unwrap();

    let (action, metrics) = Action::test_journaled_state(
        "test.system-action",
        1,
        host_privilege(),
        Arc::clone(&state),
    );
    let mut plan = vec![action];
    let store = ReceiptStore::new_for_test(fixture.system_receipt());
    let mut metadata = receipt_metadata(&[]);

    let error = run_privileged_request(&context, &altered_digest, &mut plan, &store, &mut metadata)
        .unwrap_err();

    assert_eq!(error.error_code(), "setup.plan_invalid");
    assert_eq!(metrics.mutation_calls(), 0);
    assert!(state.lock().unwrap().is_empty());
}

#[test]
fn runner_rejects_host_executable_principal_and_action_drift_before_mutation() {
    for case in [
        "host",
        "executable",
        "principal",
        "added-action",
        "changed-parameter",
    ] {
        let fixture = AuthorizationFixture::new(&format!("context-{case}"));
        let state = Arc::new(Mutex::new(Vec::new()));
        let displayed = vec![
            Action::test_journaled_state(
                "test.system-action",
                1,
                host_privilege(),
                Arc::clone(&state),
            )
            .0,
        ];
        let context = fixture.context();
        let digest = write_request(&displayed, &context).unwrap();
        let runner_context = match case {
            "host" => fixture.context_with_host("different-host"),
            "executable" => {
                let mut value = serde_json::from_slice::<serde_json::Value>(
                    &fs::read(fixture.request_path()).unwrap(),
                )
                .unwrap();
                value["executable"] = serde_json::json!(fixture.root.join("different-styrn"));
                fs::write(fixture.request_path(), serde_json::to_vec(&value).unwrap()).unwrap();
                context.clone()
            }
            "principal" => {
                let mut value = serde_json::from_slice::<serde_json::Value>(
                    &fs::read(fixture.request_path()).unwrap(),
                )
                .unwrap();
                value["principal"] = serde_json::to_value(different_principal()).unwrap();
                fs::write(fixture.request_path(), serde_json::to_vec(&value).unwrap()).unwrap();
                context.clone()
            }
            _ => context.clone(),
        };
        let (action, metrics) = Action::test_journaled_state(
            "test.system-action",
            if case == "changed-parameter" { 2 } else { 1 },
            host_privilege(),
            Arc::clone(&state),
        );
        let mut plan = vec![action];
        if case == "added-action" {
            plan.push(
                Action::test_journaled_state(
                    "test.added-system-action",
                    2,
                    host_privilege(),
                    Arc::clone(&state),
                )
                .0,
            );
        }
        let store = ReceiptStore::new_for_test(fixture.system_receipt());
        let mut metadata = receipt_metadata(&[]);

        let error =
            run_privileged_request(&runner_context, &digest, &mut plan, &store, &mut metadata)
                .unwrap_err();

        assert_eq!(error.error_code(), "setup.plan_invalid", "{case}");
        assert_eq!(metrics.mutation_calls(), 0, "{case}");
        assert!(state.lock().unwrap().is_empty(), "{case}");
        assert_eq!(store.read_snapshot().unwrap().entry_count(), 0, "{case}");
    }
}

#[test]
fn authorization_context_rejects_an_absolute_non_current_executable() {
    let fixture = AuthorizationFixture::new("wrong-context-executable");
    let result = AuthorizationContext::new_for_test(
        "host-019cb047",
        fixture.root.join("different-styrn"),
        fixture.request.clone(),
        crate::platform::resolve_current_worker_principal().unwrap(),
        "2026-09-02T12:00:00Z",
    );

    let error = match result {
        Ok(_) => panic!("non-current executable unexpectedly became trusted context"),
        Err(error) => error,
    };
    assert_eq!(error.error_code(), "setup.plan_invalid");
}

#[test]
fn authorization_context_rejects_secret_shaped_request_parent_without_echo() {
    let fixture = AuthorizationFixture::new("secret-request-parent");
    let request = fixture
        .root
        .join("api_key=do-not-echo")
        .join("authorization-request.json");
    let result = AuthorizationContext::new_for_test(
        "host-019cb047",
        fixture.executable.clone(),
        request,
        crate::platform::resolve_current_worker_principal().unwrap(),
        "2026-09-02T12:00:00Z",
    );

    let error = result.unwrap_err();
    assert_eq!(error.error_code(), "setup.plan_invalid");
    assert!(!error.to_string().contains("do-not-echo"));
}

#[test]
fn authorization_is_bound_to_exact_user_and_system_receipt_stores() {
    let fixture = AuthorizationFixture::new("store-binding");
    let other = AuthorizationFixture::new("other-store-binding");
    let state = Arc::new(Mutex::new(Vec::new()));
    let (ordinary, ordinary_metrics) =
        Action::test_journaled_state("test.user-action", 1, Privilege::None, Arc::clone(&state));
    let mut ordinary_plan = vec![ordinary];
    let wrong_user_store = ReceiptStore::new_user_for_test(other.user_receipt());
    let mut metadata = receipt_metadata(&[]);
    let mut invoker = SpyInvoker::default();

    let parent_result = execute_with_authorization(
        &mut ordinary_plan,
        &wrong_user_store,
        &mut metadata,
        &fixture.context(),
        AuthorizationOptions::interactive_decline(),
        &mut invoker,
    );
    let parent_error = match parent_result {
        Ok(_) => panic!("mismatched user store unexpectedly authorized execution"),
        Err(error) => error,
    };
    assert_eq!(parent_error.error_code(), "setup.plan_invalid");
    assert_eq!(ordinary_metrics.mutation_calls(), 0);
    assert!(state.lock().unwrap().is_empty());
    assert!(!other.user_receipt().exists());

    let displayed = vec![
        Action::test_journaled_state(
            "test.system-action",
            2,
            host_privilege(),
            Arc::clone(&state),
        )
        .0,
    ];
    let context = fixture.context();
    let digest = write_request(&displayed, &context).unwrap();
    let (privileged, privileged_metrics) = Action::test_journaled_state(
        "test.system-action",
        2,
        host_privilege(),
        Arc::clone(&state),
    );
    let mut privileged_plan = vec![privileged];
    let wrong_system_store = ReceiptStore::new_user_for_test(fixture.user_receipt());
    let mut metadata = receipt_metadata(&[]);

    let child_error = run_privileged_request(
        &context,
        &digest,
        &mut privileged_plan,
        &wrong_system_store,
        &mut metadata,
    )
    .unwrap_err();
    assert_eq!(child_error.error_code(), "setup.plan_invalid");
    assert_eq!(privileged_metrics.mutation_calls(), 0);
    assert!(state.lock().unwrap().is_empty());
    assert!(fixture.request_path().exists());
    assert!(!fixture.user_receipt().exists());
}

#[cfg(unix)]
#[test]
fn runner_rejects_symlink_fifo_directory_and_insecure_request_nodes() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    for case in ["symlink", "fifo", "directory", "mode"] {
        let fixture = AuthorizationFixture::new(&format!("unsafe-{case}"));
        let state = Arc::new(Mutex::new(Vec::new()));
        let displayed = vec![
            Action::test_journaled_state(
                "test.system-action",
                1,
                host_privilege(),
                Arc::clone(&state),
            )
            .0,
        ];
        let context = fixture.context();
        let digest = write_request(&displayed, &context).unwrap();
        let original = fs::read(fixture.request_path()).unwrap();
        fs::remove_file(fixture.request_path()).unwrap();
        match case {
            "symlink" => {
                let target = fixture.root.join("target.json");
                fs::write(&target, &original).unwrap();
                symlink(target, fixture.request_path()).unwrap();
            }
            "fifo" => {
                let path =
                    std::ffi::CString::new(fixture.request_path().as_os_str().as_encoded_bytes())
                        .unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
            "directory" => fs::create_dir(fixture.request_path()).unwrap(),
            "mode" => {
                fs::write(fixture.request_path(), original).unwrap();
                fs::set_permissions(fixture.request_path(), fs::Permissions::from_mode(0o644))
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let (action, metrics) = Action::test_journaled_state(
            "test.system-action",
            1,
            host_privilege(),
            Arc::clone(&state),
        );
        let mut plan = vec![action];
        let store = ReceiptStore::new_for_test(fixture.system_receipt());
        let mut metadata = receipt_metadata(&[]);

        let error = run_privileged_request(&context, &digest, &mut plan, &store, &mut metadata)
            .unwrap_err();

        assert_eq!(error.error_code(), "setup.plan_invalid", "{case}");
        assert_eq!(metrics.mutation_calls(), 0, "{case}");
        assert!(state.lock().unwrap().is_empty(), "{case}");
    }
}

fn assert_complete_pending_projection(
    label: &str,
    options: AuthorizationOptions,
    expected_status: PrivilegedStatus,
    expected_invocations: usize,
) {
    let fixture = AuthorizationFixture::new(label);
    let store = ReceiptStore::new_user_for_test(fixture.user_receipt());
    let state = Arc::new(Mutex::new(Vec::new()));
    let (privileged_intrinsic, privileged_intrinsic_metrics) = Action::test_named_needs_human(
        "test.system-approval",
        host_privilege(),
        Arc::clone(&state),
        NeedsHuman::new(
            HumanInstructions::new("Approve the protected system setting, then rerun setup.")
                .unwrap(),
            Some(ScriptFragment::DeferredAction(
                crate::setup::action::ActionName::parse("test.system-fragment").unwrap(),
            )),
        )
        .with_severity(PendingSeverity::Info),
    );
    let (ordinary_todo, ordinary_todo_metrics) =
        Action::test_journaled_state("test.user-action", 1, Privilege::None, Arc::clone(&state));
    let (ordinary_pending, ordinary_pending_metrics) = Action::test_named_needs_human(
        "test.user-approval",
        Privilege::None,
        Arc::clone(&state),
        NeedsHuman::new(
            HumanInstructions::new("Approve the user setting, then rerun setup.").unwrap(),
            None,
        ),
    );
    let (privileged_todo, privileged_todo_metrics) = Action::test_journaled_state(
        "test.system-action",
        2,
        host_privilege(),
        Arc::clone(&state),
    );
    let mut plan = vec![
        privileged_intrinsic,
        ordinary_todo,
        ordinary_pending,
        privileged_todo,
    ];
    let mut metadata = ReceiptMetadataSource::for_test([
        (
            "019cb047-3c00-7000-8000-000000000021",
            "2026-09-02T12:00:00Z",
        ),
        (
            "019cb047-3c00-7000-8000-000000000022",
            "2026-09-02T12:00:01Z",
        ),
        (
            "019cb047-3c00-7000-8000-000000000023",
            "2026-09-02T12:00:02Z",
        ),
        (
            "019cb047-3c00-7000-8000-000000000024",
            "2026-09-02T12:00:03Z",
        ),
    ]);
    let mut invoker = SpyInvoker::default();

    let report = execute_with_authorization(
        &mut plan,
        &store,
        &mut metadata,
        &fixture.context(),
        options,
        &mut invoker,
    )
    .unwrap();

    assert_eq!(report.privileged_status(), expected_status);
    assert_eq!(invoker.calls(), expected_invocations);
    assert!(!report.everything_ready());
    assert_eq!(report.ordinary().applied_count(), 1);
    assert_eq!(report.ordinary().recovered_count(), 0);
    assert_eq!(report.ordinary().noop_count(), 0);
    assert_eq!(
        report
            .pending()
            .iter()
            .map(|pending| pending.id().as_str())
            .collect::<Vec<_>>(),
        [
            "test.system-approval",
            "test.user-approval",
            "test.system-action"
        ]
    );
    assert_eq!(report.pending()[0].severity(), PendingSeverity::Info);
    assert_eq!(
        report.pending()[0].needs_human().instructions().as_str(),
        "Approve the protected system setting, then rerun setup."
    );
    assert_eq!(
        report.pending()[0].fragment_action_id(),
        Some("test.system-fragment")
    );
    assert_eq!(report.pending()[1].severity(), PendingSeverity::Warning);
    assert_eq!(
        report.pending()[1].needs_human().instructions().as_str(),
        "Approve the user setting, then rerun setup."
    );
    assert_eq!(report.pending()[2].severity(), PendingSeverity::Warning);
    assert_eq!(
        report.pending()[2].needs_human().instructions().as_str(),
        AUTHORIZATION_PENDING_INSTRUCTIONS
    );
    assert_eq!(ordinary_todo_metrics.mutation_calls(), 1);
    assert_eq!(privileged_intrinsic_metrics.mutation_calls(), 0);
    assert_eq!(ordinary_pending_metrics.mutation_calls(), 0);
    assert_eq!(privileged_todo_metrics.mutation_calls(), 0);
    assert_eq!(*state.lock().unwrap(), vec![1]);

    let timestamp = Utc.with_ymd_and_hms(2026, 9, 2, 12, 0, 4).unwrap();
    let default = crate::setup::pending::PendingPolicy::default()
        .evaluate(timestamp, report.completion())
        .unwrap();
    let strict = crate::setup::pending::PendingPolicy::new(true)
        .evaluate(timestamp, report.completion())
        .unwrap();
    assert_eq!(default.exit_code().as_i32(), 0);
    assert_eq!(strict.exit_code().as_i32(), 13);
    let default_json: serde_json::Value =
        serde_json::from_str(&crate::output::to_json(default.envelope()).unwrap()).unwrap();
    let strict_json: serde_json::Value =
        serde_json::from_str(&crate::output::to_json(strict.envelope()).unwrap()).unwrap();
    let expected_pending = serde_json::json!([
        {
            "id": "test.system-approval",
            "severity": "info",
            "message": "Approve the protected system setting, then rerun setup.",
            "deferred_action": "test.system-fragment"
        },
        {
            "id": "test.user-approval",
            "severity": "warning",
            "message": "Approve the user setting, then rerun setup."
        },
        {
            "id": "test.system-action",
            "severity": "warning",
            "message": AUTHORIZATION_PENDING_INSTRUCTIONS
        }
    ]);
    assert_eq!(default_json["ok"], true);
    assert_eq!(default_json["data"]["pending"], expected_pending);
    assert_eq!(default_json["warnings"].as_array().unwrap().len(), 3);
    assert!(default_json["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|warning| warning["code"] == "setup.needs_human"));
    assert_eq!(strict_json["ok"], false);
    assert!(strict_json["data"].is_null());
    assert_eq!(strict_json["errors"][0]["code"], "setup.needs_human");
    assert_eq!(
        strict_json["errors"][0]["details"]["pending"],
        expected_pending
    );
    assert_eq!(strict_json["warnings"], default_json["warnings"]);

    let mut human = Vec::new();
    crate::setup::pending::render_human(&mut human, report.completion()).unwrap();
    assert_eq!(
        String::from_utf8(human).unwrap(),
        concat!(
            "Pending actions requiring your attention:\n",
            "- [info] test.system-approval: Approve the protected system setting, then rerun setup.\n",
            "  deferred action: test.system-fragment; not rendered or executed\n",
            "- [warning] test.user-approval: Approve the user setting, then rerun setup.\n",
            "- [warning] test.system-action: Authorize the displayed system change, then rerun setup.\n",
        )
    );

    let manifest_path = fixture.manifest_path();
    let principal = crate::platform::resolve_current_worker_principal().unwrap();
    let manifest_store =
        crate::manifest::MachineManifestStore::new_user(&manifest_path, principal).unwrap();
    let mut draft = pending_manifest_draft_for_current_user();
    crate::setup::pending::publish_manifest(
        &manifest_store,
        &store,
        &mut draft,
        report.completion(),
        &mut receipt_metadata(&[(
            "019cb047-3c00-7000-8000-000000000025",
            "2026-09-02T12:00:04Z",
        )]),
    )
    .unwrap();
    let published = manifest_store.read().unwrap().manifest;
    let manifest_pending = published.pending_actions.as_ref().unwrap();
    assert_eq!(manifest_pending.len(), 3);
    assert_eq!(
        manifest_pending
            .iter()
            .map(|pending| pending.id.as_str())
            .collect::<Vec<_>>(),
        [
            "test.system-approval",
            "test.user-approval",
            "test.system-action"
        ]
    );
    assert_eq!(
        manifest_pending
            .iter()
            .map(|pending| pending.message.as_str())
            .collect::<Vec<_>>(),
        [
            "Approve the protected system setting, then rerun setup.",
            "Approve the user setting, then rerun setup.",
            AUTHORIZATION_PENDING_INSTRUCTIONS
        ]
    );
    assert_eq!(
        manifest_pending[0].severity,
        crate::manifest::PendingSeverity::Info
    );
    assert_eq!(
        manifest_pending[1].severity,
        crate::manifest::PendingSeverity::Warning
    );
    assert_eq!(
        manifest_pending[2].severity,
        crate::manifest::PendingSeverity::Warning
    );

    let receipt = serde_json::from_slice::<serde_json::Value>(
        &store.read_snapshot().unwrap().to_json().unwrap(),
    )
    .unwrap();
    assert_eq!(
        receipt["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["action"]["parameters"]["action_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "test.user-action",
            "test.user-approval",
            "test.system-approval",
            "test.system-action"
        ]
    );
    assert_eq!(
        receipt["pending_publications"][0]["pending"],
        serde_json::json!([
            {
                "action_id": "test.system-approval",
                "entry_id": "019cb047-3c00-7000-8000-000000000023"
            },
            {
                "action_id": "test.user-approval",
                "entry_id": "019cb047-3c00-7000-8000-000000000022"
            },
            {
                "action_id": "test.system-action",
                "entry_id": "019cb047-3c00-7000-8000-000000000024"
            }
        ])
    );
}

fn receipt_metadata(values: &[(&str, &str)]) -> ReceiptMetadataSource {
    match values {
        [] => ReceiptMetadataSource::for_test([]),
        [(id, timestamp)] => ReceiptMetadataSource::for_test([(*id, *timestamp)]),
        [(first_id, first_timestamp), (second_id, second_timestamp)] => {
            ReceiptMetadataSource::for_test([
                (*first_id, *first_timestamp),
                (*second_id, *second_timestamp),
            ])
        }
        _ => panic!("test helper supports up to two receipt metadata values"),
    }
}

fn host_privilege() -> Privilege {
    #[cfg(target_os = "windows")]
    {
        Privilege::Admin
    }
    #[cfg(not(target_os = "windows"))]
    {
        Privilege::Root
    }
}

fn host_setup_privilege() -> crate::platform::SetupHostPrivilege {
    #[cfg(target_os = "windows")]
    {
        crate::platform::SetupHostPrivilege::Administrator
    }
    #[cfg(not(target_os = "windows"))]
    {
        crate::platform::SetupHostPrivilege::Root
    }
}

struct SpyPreparedRunner {
    expected_privilege: Privilege,
    calls: usize,
}

impl SpyPreparedRunner {
    fn new(expected_privilege: Privilege) -> Self {
        Self {
            expected_privilege,
            calls: 0,
        }
    }
}

impl PreparedActionRunner for SpyPreparedRunner {
    fn execute_prepared_and_bind<Bind>(
        &mut self,
        action: &mut Action,
        expected: &ActionEffect,
        bind: Bind,
    ) -> Result<(MutationCompletion, DurableReceiptBinding), ApplyPlanError>
    where
        Bind: for<'authority> FnOnce(
            VerifiedActionEffect<'authority>,
        ) -> Result<DurableReceiptBinding, ReceiptStoreError>,
    {
        assert_eq!(action.privilege(), self.expected_privilege);
        self.calls += 1;
        action
            .execute_prepared_and_bind(|verified| {
                assert_eq!(verified.effect(), expected);
                bind(verified)
            })
            .map_err(|error| match error {
                PreparedExecutionError::Action(error) => error.into(),
                PreparedExecutionError::ReceiptConflict => ReceiptStoreError::IntentConflict.into(),
                PreparedExecutionError::Binding(error) => error.into(),
            })
    }
}

#[derive(Default)]
struct FailOncePreparedRunner {
    calls: usize,
}

impl PreparedActionRunner for FailOncePreparedRunner {
    fn execute_prepared_and_bind<Bind>(
        &mut self,
        action: &mut Action,
        expected: &ActionEffect,
        bind: Bind,
    ) -> Result<(MutationCompletion, DurableReceiptBinding), ApplyPlanError>
    where
        Bind: for<'authority> FnOnce(
            VerifiedActionEffect<'authority>,
        ) -> Result<DurableReceiptBinding, ReceiptStoreError>,
    {
        self.calls += 1;
        if self.calls == 1 {
            return Err(ActionError::apply_failed(action.name().clone()).into());
        }
        action
            .execute_prepared_and_bind(|verified| {
                assert_eq!(verified.effect(), expected);
                bind(verified)
            })
            .map_err(|error| match error {
                PreparedExecutionError::Action(error) => error.into(),
                PreparedExecutionError::ReceiptConflict => ReceiptStoreError::IntentConflict.into(),
                PreparedExecutionError::Binding(error) => error.into(),
            })
    }
}

#[derive(Default)]
struct SpyInvoker {
    calls: usize,
    executable: Option<PathBuf>,
    request_path: Option<PathBuf>,
    request_digest: Option<String>,
    failure: Option<SpyInvocationFailure>,
}

impl SpyInvoker {
    fn failing() -> Self {
        Self::failing_with(SpyInvocationFailure::Cancelled)
    }

    fn failing_with(failure: SpyInvocationFailure) -> Self {
        Self {
            failure: Some(failure),
            ..Self::default()
        }
    }

    fn calls(&self) -> usize {
        self.calls
    }

    fn executable(&self) -> Option<&Path> {
        self.executable.as_deref()
    }

    fn request_path(&self) -> Option<&Path> {
        self.request_path.as_deref()
    }

    fn request_digest(&self) -> Option<&str> {
        self.request_digest.as_deref()
    }
}

impl AuthorizationInvoker for SpyInvoker {
    fn invoke(
        &mut self,
        executable: &Path,
        request_path: &Path,
        request_digest: &str,
    ) -> Result<(), AuthorizationInvocationError> {
        self.calls += 1;
        self.executable = Some(executable.to_path_buf());
        self.request_path = Some(request_path.to_path_buf());
        self.request_digest = Some(request_digest.to_owned());
        match self.failure {
            None => Ok(()),
            Some(SpyInvocationFailure::Cancelled) => Err(AuthorizationInvocationError::Failed),
            Some(SpyInvocationFailure::Launch) => Err(AuthorizationInvocationError::Launch(
                std::io::Error::other("injected launcher failure"),
            )),
            Some(SpyInvocationFailure::Child) => Err(AuthorizationInvocationError::ChildFailed {
                exit_code: Some(13),
            }),
        }
    }
}

#[derive(Clone, Copy)]
enum SpyInvocationFailure {
    Cancelled,
    Launch,
    Child,
}

struct AuthorizationFixture {
    root: PathBuf,
    user_receipt: PathBuf,
    system_receipt: PathBuf,
    request: PathBuf,
    executable: PathBuf,
}

impl AuthorizationFixture {
    fn new(_label: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "styrn-setup-request-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        let state = root.join("state/styrn");
        let system_state = root.join("system/styrn");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&system_state).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(root.join("state"), fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(root.join("system"), fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&system_state, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self {
            user_receipt: state.join("receipt.json"),
            system_receipt: system_state.join("receipt.json"),
            request: state.join("authorization-request.json"),
            executable: std::env::current_exe().unwrap(),
            root,
        }
    }

    fn user_receipt(&self) -> &Path {
        &self.user_receipt
    }

    fn request_path(&self) -> &Path {
        &self.request
    }

    fn manifest_path(&self) -> PathBuf {
        self.request.with_file_name("machine.toml")
    }

    fn system_receipt(&self) -> &Path {
        &self.system_receipt
    }

    fn context(&self) -> AuthorizationContext {
        self.context_at("2026-09-02T12:00:00Z")
    }

    fn context_at(&self, now: &str) -> AuthorizationContext {
        AuthorizationContext::new_for_test(
            "host-019cb047",
            self.executable.clone(),
            self.request.clone(),
            crate::platform::resolve_current_worker_principal().unwrap(),
            now,
        )
        .unwrap()
    }

    fn context_with_host(&self, host: &str) -> AuthorizationContext {
        AuthorizationContext::new_for_test(
            host,
            self.executable.clone(),
            self.request.clone(),
            crate::platform::resolve_current_worker_principal().unwrap(),
            "2026-09-02T12:00:00Z",
        )
        .unwrap()
    }
}

fn different_principal() -> crate::platform::WorkerPrincipal {
    #[cfg(unix)]
    {
        let current = crate::platform::resolve_current_worker_principal().unwrap();
        let uid = current.unix_uid().unwrap().saturating_add(1).max(1);
        crate::platform::WorkerPrincipal::new(
            crate::platform::PrincipalKind::UnixUid,
            uid.to_string(),
            "different-principal",
            crate::platform::WorkerAccountPolicy::CurrentUser,
        )
        .unwrap()
    }
    #[cfg(windows)]
    {
        crate::platform::WorkerPrincipal::new(
            crate::platform::PrincipalKind::WindowsSid,
            "S-1-5-21-1-2-3-4242",
            "different-principal",
            crate::platform::WorkerAccountPolicy::CurrentUser,
        )
        .unwrap()
    }
}

impl Drop for AuthorizationFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn pending_manifest_draft_for_current_user() -> crate::manifest::MachineManifestDraft {
    let mut draft = crate::manifest::MachineManifest::parse_toml(include_str!(
        "../../../../examples/machine.controller-worker.toml"
    ))
    .unwrap()
    .without_machine_id();
    let principal = crate::platform::resolve_current_worker_principal().unwrap();

    #[cfg(target_os = "linux")]
    let operating_system = crate::manifest::OperatingSystem::Linux;
    #[cfg(target_os = "macos")]
    let operating_system = crate::manifest::OperatingSystem::Macos;
    #[cfg(target_os = "windows")]
    let operating_system = crate::manifest::OperatingSystem::Windows;
    draft.platform.os = operating_system;
    crate::manifest::CurrentUserWorkerManifestCandidate::derive(&draft, &principal)
        .unwrap()
        .into_draft()
}
