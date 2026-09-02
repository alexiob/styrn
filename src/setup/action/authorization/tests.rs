use super::*;
use crate::setup::{
    action::{Action, HumanInstructions, NeedsHuman, Privilege},
    receipt::{ReceiptMetadataSource, ReceiptStore},
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

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
    assert!(second.ordinary().is_nothing_to_do());
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
        AuthorizationOptions::interactive_decline(),
        &mut invoker,
    )
    .unwrap();

    assert_eq!(report.ordinary().applied_count(), 1);
    assert_eq!(
        report.privileged_status(),
        PrivilegedStatus::Pending { count: 1 }
    );
    assert!(!report.everything_ready());
    assert_eq!(invoker.calls(), 0);
    assert_eq!(ordinary_metrics.mutation_calls(), 1);
    assert_eq!(privileged_metrics.mutation_calls(), 0);
    assert_eq!(*state.lock().unwrap(), vec![1]);
    assert_eq!(store.read_snapshot().unwrap().entry_count(), 1);
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
        let mut metadata = receipt_metadata(&[]);
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
        assert_eq!(invoker.calls(), 0);
        assert_eq!(metrics.mutation_calls(), 0);
        assert!(state.lock().unwrap().is_empty());
        assert!(!fixture.request_path().exists());
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
        let mut metadata = receipt_metadata(&[]);
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
    }
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
fn privileged_needs_human_does_not_prompt_and_is_not_reported_ready() {
    let fixture = AuthorizationFixture::new("privileged-needs-human");
    let store = ReceiptStore::new_user_for_test(fixture.user_receipt());
    let state = Arc::new(Mutex::new(Vec::new()));
    let (action, metrics) = Action::test_needs_human(
        host_privilege(),
        Arc::clone(&state),
        NeedsHuman::new(
            HumanInstructions::new("Approve the operating-system setting.").unwrap(),
            None,
        ),
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

    assert_eq!(
        report.privileged_status(),
        PrivilegedStatus::NeedsHuman { count: 1 }
    );
    assert!(!report.everything_ready());
    assert_eq!(invoker.calls(), 0);
    assert_eq!(metrics.mutation_calls(), 0);
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
    )
    .unwrap();

    let error = write_request(&displayed, &context).unwrap_err();

    assert_eq!(error.error_code(), "setup.plan_invalid");
    assert!(!error.to_string().contains("do-not-write"));
    assert!(!fixture.request_path().exists());
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

fn receipt_metadata(values: &[(&str, &str)]) -> ReceiptMetadataSource {
    match values {
        [] => ReceiptMetadataSource::for_test([]),
        [(id, timestamp)] => ReceiptMetadataSource::for_test([(*id, *timestamp)]),
        _ => panic!("test helper supports zero or one receipt metadata value"),
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

#[derive(Default)]
struct SpyInvoker {
    calls: usize,
    executable: Option<PathBuf>,
    request_path: Option<PathBuf>,
    request_digest: Option<String>,
}

impl SpyInvoker {
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
        Ok(())
    }
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
        )
        .unwrap()
    }
    #[cfg(windows)]
    {
        crate::platform::WorkerPrincipal::new(
            crate::platform::PrincipalKind::WindowsSid,
            "S-1-5-21-1-2-3-4242",
            "different-principal",
        )
        .unwrap()
    }
}

impl Drop for AuthorizationFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
