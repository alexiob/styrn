use super::*;
use crate::setup::{
    action::Privilege,
    probe::{test_support, ProbeFailure, ProbeId, ProbeStatus},
};
use std::io::Cursor;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

fn id(value: &str) -> ProbeId {
    ProbeId::parse(value).expect("test probe ID must be valid")
}

fn action(
    subject: &str,
    name: &str,
    description: &str,
    privilege: Privilege,
    operation: PlanOperation,
) -> DesiredAction {
    DesiredAction::new(id(subject), name, description, privilege, operation)
        .expect("test desired action must be valid")
}

fn converge(subject: &str, component: &str) -> DesiredChange {
    DesiredChange::converge(
        id(subject),
        component,
        action(
            subject,
            "test.install",
            "install the component",
            Privilege::Admin,
            PlanOperation::Create,
        ),
        action(
            subject,
            "test.repair",
            "repair the component",
            Privilege::Root,
            PlanOperation::Reconfigure,
        ),
        action(
            subject,
            "test.done",
            "component is healthy",
            Privilege::None,
            PlanOperation::Done,
        ),
    )
    .expect("test desired convergence must be valid")
}

fn converge_with_done(
    subject: &str,
    component: &str,
    name: &str,
    description: &str,
    privilege: Privilege,
) -> DesiredChange {
    DesiredChange::converge(
        id(subject),
        component,
        action(
            subject,
            &format!("{name}.install"),
            "install the component",
            privilege,
            PlanOperation::Create,
        ),
        action(
            subject,
            &format!("{name}.repair"),
            "repair the component",
            privilege,
            PlanOperation::Reconfigure,
        ),
        action(
            subject,
            &format!("{name}.done"),
            description,
            privilege,
            PlanOperation::Done,
        ),
    )
    .expect("test desired convergence must be valid")
}

#[test]
fn ordered_diff_renders_grouped_create_reconfigure_and_done_lines() {
    let calls = Arc::new(AtomicUsize::new(0));
    let catalog = test_support::catalog(vec![
        test_support::TestProbe::fixed("tool.tailscale", ProbeStatus::Absent, Arc::clone(&calls)),
        test_support::TestProbe::fixed(
            "service.sshd",
            ProbeStatus::Present {
                version: Some("9.9.0".to_owned()),
                healthy: false,
            },
            Arc::clone(&calls),
        ),
        test_support::TestProbe::fixed(
            "tool.git",
            ProbeStatus::Present {
                version: Some("2.50.0".to_owned()),
                healthy: true,
            },
            Arc::clone(&calls),
        ),
    ]);
    let desired = DesiredState::new(vec![
        DesiredChange::converge(
            id("tool.tailscale"),
            "tailscale",
            action(
                "tool.tailscale",
                "tailscale.install",
                "install tailscale",
                Privilege::Admin,
                PlanOperation::Create,
            ),
            action(
                "tool.tailscale",
                "tailscale.repair",
                "repair tailscale",
                Privilege::Admin,
                PlanOperation::Reconfigure,
            ),
            action(
                "tool.tailscale",
                "tailscale.done",
                "tailscale is healthy",
                Privilege::None,
                PlanOperation::Done,
            ),
        )
        .unwrap(),
        DesiredChange::converge(
            id("service.sshd"),
            "sshd",
            action(
                "service.sshd",
                "sshd.install",
                "install sshd",
                Privilege::Root,
                PlanOperation::Create,
            ),
            action(
                "service.sshd",
                "sshd.repair",
                "set key-only authentication",
                Privilege::Root,
                PlanOperation::Reconfigure,
            ),
            action(
                "service.sshd",
                "sshd.done",
                "sshd is healthy",
                Privilege::None,
                PlanOperation::Done,
            ),
        )
        .unwrap(),
        DesiredChange::converge(
            id("tool.git"),
            "tailscale",
            action(
                "tool.git",
                "git.install",
                "install git",
                Privilege::None,
                PlanOperation::Create,
            ),
            action(
                "tool.git",
                "git.repair",
                "repair git",
                Privilege::None,
                PlanOperation::Reconfigure,
            ),
            action(
                "tool.git",
                "git.done",
                "git is healthy",
                Privilege::None,
                PlanOperation::Done,
            ),
        )
        .unwrap(),
    ]);

    let observed = catalog.observe();
    let plan = SetupPlan::compute(&observed, &desired).unwrap();
    assert_eq!(
        plan.entries()
            .map(|entry| entry.subject().as_str())
            .collect::<Vec<_>>(),
        ["tool.tailscale", "service.sshd", "tool.git"]
    );
    assert_eq!(
        plan.entries()
            .map(|entry| entry.operation())
            .collect::<Vec<_>>(),
        [
            PlanOperation::Create,
            PlanOperation::Reconfigure,
            PlanOperation::Done
        ]
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    let mut rendered = Vec::new();
    render_dry_run(&plan, &mut rendered).unwrap();
    assert_eq!(
        String::from_utf8(rendered).unwrap(),
        "tailscale:\n  + install tailscale [admin]\n  ✓ git is healthy\nsshd:\n  ~ set key-only authentication [sudo]\n"
    );
}

#[test]
fn dry_run_probes_once_writes_only_to_its_writer_and_never_mutates_or_journals() {
    let calls = Arc::new(AtomicUsize::new(0));
    let state = Arc::new(Mutex::new(vec![0]));
    let catalog = test_support::catalog(vec![test_support::TestProbe::stateful_absence(
        "state.worker",
        Arc::clone(&state),
        Arc::clone(&calls),
    )]);
    let desired = DesiredState::new(vec![converge("state.worker", "worker")]);
    let receipt = std::env::temp_dir().join(format!(
        "styrn-plan-receipt-sentinel-{}-{}",
        std::process::id(),
        calls.load(Ordering::SeqCst)
    ));
    let _ = std::fs::remove_file(&receipt);
    let before = state.lock().unwrap().clone();
    let mut output = Cursor::new(Vec::new());

    let plan = dry_run(&catalog, &desired, &mut output).unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(*state.lock().unwrap(), before);
    assert!(matches!(
        catalog.observe().get(&id("state.worker")).unwrap().status(),
        ProbeStatus::Absent
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(!receipt.exists());
    assert_eq!(plan.entries().len(), 1);
    assert_eq!(
        String::from_utf8(output.into_inner()).unwrap(),
        "worker:\n  + install the component [admin]\n"
    );
}

#[test]
fn unknowable_observation_refuses_the_plan_without_echoing_its_raw_reason() {
    let secret = "token=do-not-echo";
    let catalog = test_support::catalog(vec![test_support::TestProbe::fixed(
        "state.protected",
        ProbeStatus::Unknowable {
            reason: secret.to_owned(),
        },
        Arc::new(AtomicUsize::new(0)),
    )]);
    let desired = DesiredState::new(vec![converge("state.protected", "protected")]);

    let error = SetupPlan::compute(&catalog.observe(), &desired).unwrap_err();

    assert_eq!(error, PlanError::UnknowableObservation);
    assert!(!error.to_string().contains(secret));
}

#[test]
fn missing_or_duplicate_desired_subjects_refuse_before_any_rendering() {
    let catalog = test_support::catalog(vec![test_support::TestProbe::fixed(
        "tool.present",
        ProbeStatus::Present {
            version: None,
            healthy: true,
        },
        Arc::new(AtomicUsize::new(0)),
    )]);
    let observed = catalog.observe();
    let missing = DesiredState::new(vec![converge("tool.missing", "missing")]);
    let duplicate = DesiredState::new(vec![
        converge("tool.present", "first"),
        converge("tool.present", "second"),
    ]);

    for desired in [&missing, &duplicate] {
        let mut writer = Vec::new();
        assert!(dry_run_observed(&observed, desired, &mut writer).is_err());
        assert!(writer.is_empty());
    }
    assert_eq!(
        SetupPlan::compute(&observed, &missing).unwrap_err(),
        PlanError::MissingObservation
    );
    assert_eq!(
        SetupPlan::compute(&observed, &duplicate).unwrap_err(),
        PlanError::DuplicateDesiredSubject
    );
}

#[test]
fn status_mapping_keeps_absent_unhealthy_and_broken_distinct() {
    let catalog = test_support::catalog(vec![
        test_support::TestProbe::fixed(
            "tool.absent",
            ProbeStatus::Absent,
            Arc::new(AtomicUsize::new(0)),
        ),
        test_support::TestProbe::fixed(
            "tool.healthy",
            ProbeStatus::Present {
                version: None,
                healthy: true,
            },
            Arc::new(AtomicUsize::new(0)),
        ),
        test_support::TestProbe::fixed(
            "tool.unhealthy",
            ProbeStatus::Present {
                version: None,
                healthy: false,
            },
            Arc::new(AtomicUsize::new(0)),
        ),
        test_support::TestProbe::fixed(
            "tool.broken",
            ProbeStatus::Broken {
                reason: "corrupt state".to_owned(),
            },
            Arc::new(AtomicUsize::new(0)),
        ),
    ]);
    let desired = DesiredState::new(vec![
        converge("tool.absent", "absent"),
        converge("tool.healthy", "healthy"),
        converge("tool.unhealthy", "unhealthy"),
        converge("tool.broken", "broken"),
    ]);

    let plan = SetupPlan::compute(&catalog.observe(), &desired).unwrap();
    assert_eq!(
        plan.entries()
            .map(|entry| entry.operation())
            .collect::<Vec<_>>(),
        [
            PlanOperation::Create,
            PlanOperation::Done,
            PlanOperation::Reconfigure,
            PlanOperation::Reconfigure
        ]
    );
}

#[test]
fn converge_rejects_status_inverting_create_and_done_templates() {
    let absent_done = DesiredChange::converge(
        id("tool.absent"),
        "absent",
        action(
            "tool.absent",
            "absent.done",
            "claim absent component is done",
            Privilege::None,
            PlanOperation::Done,
        ),
        action(
            "tool.absent",
            "absent.repair",
            "repair absent component",
            Privilege::None,
            PlanOperation::Reconfigure,
        ),
        action(
            "tool.absent",
            "absent.healthy",
            "component is healthy",
            Privilege::None,
            PlanOperation::Done,
        ),
    );
    let healthy_create = DesiredChange::converge(
        id("tool.healthy"),
        "healthy",
        action(
            "tool.healthy",
            "healthy.install",
            "install healthy component",
            Privilege::None,
            PlanOperation::Create,
        ),
        action(
            "tool.healthy",
            "healthy.repair",
            "repair healthy component",
            Privilege::None,
            PlanOperation::Reconfigure,
        ),
        action(
            "tool.healthy",
            "healthy.create",
            "create healthy component",
            Privilege::None,
            PlanOperation::Create,
        ),
    );

    assert_eq!(absent_done.unwrap_err(), PlanError::InvalidCrossLink);
    assert_eq!(healthy_create.unwrap_err(), PlanError::InvalidCrossLink);
}

#[test]
fn exceptional_lines_require_their_declared_observed_states() {
    let exceptional = [
        DesiredChange::needs_human(
            id("tool.human"),
            "human",
            action(
                "tool.human",
                "human.login",
                "authenticate in browser",
                Privilege::None,
                PlanOperation::NeedsHuman,
            ),
        )
        .unwrap(),
        DesiredChange::skipped(
            id("tool.skip"),
            "skip",
            action(
                "tool.skip",
                "skip.optional",
                "enable with configuration",
                Privilege::None,
                PlanOperation::Skipped,
            ),
        )
        .unwrap(),
        DesiredChange::remove(
            id("tool.remove"),
            "remove",
            action(
                "tool.remove",
                "remove.old",
                "remove old component",
                Privilege::Admin,
                PlanOperation::Remove,
            ),
        )
        .unwrap(),
    ];

    for status in [
        ProbeStatus::Present {
            version: None,
            healthy: false,
        },
        ProbeStatus::Broken {
            reason: "inconsistent state".to_owned(),
        },
    ] {
        for change in &exceptional[1..] {
            let catalog = test_support::catalog(vec![test_support::TestProbe::fixed(
                change.subject.as_str(),
                status.clone(),
                Arc::new(AtomicUsize::new(0)),
            )]);
            let desired = DesiredState::new(vec![change.clone()]);

            assert_eq!(
                SetupPlan::compute(&catalog.observe(), &desired).unwrap_err(),
                PlanError::ExceptionalObservationMismatch
            );
        }
    }
}

#[test]
fn remote_login_observation_failures_truthfully_require_human_action_without_elevation() {
    const INSTRUCTIONS: &str =
        "System Settings → General → Sharing → Remote Login → on; then re-run styrn doctor.";

    enum SyntheticObservation {
        Status(ProbeStatus),
        Failure(ProbeFailure),
    }

    let cases = [
        SyntheticObservation::Status(ProbeStatus::Broken {
            reason: "automation was unavailable".to_owned(),
        }),
        SyntheticObservation::Failure(ProbeFailure::missing_prerequisite(
            "launchctl was not installed",
        )),
        SyntheticObservation::Failure(ProbeFailure::permission_denied(
            "sharing preferences were revoked",
        )),
        SyntheticObservation::Status(ProbeStatus::Unknowable {
            reason: "remote login state was unknowable".to_owned(),
        }),
    ];

    for (index, observation) in cases.into_iter().enumerate() {
        let calls = Arc::new(AtomicUsize::new(0));
        let probe = match observation {
            SyntheticObservation::Status(status) => {
                test_support::TestProbe::fixed("macos.remote-login", status, Arc::clone(&calls))
            }
            SyntheticObservation::Failure(failure) => {
                test_support::TestProbe::failure("macos.remote-login", failure, Arc::clone(&calls))
            }
        };
        let catalog = test_support::catalog(vec![probe]);
        let desired = DesiredState::new(vec![DesiredChange::needs_human(
            id("macos.remote-login"),
            "Remote Login",
            action(
                "macos.remote-login",
                "macos.remote-login-enable",
                INSTRUCTIONS,
                Privilege::None,
                PlanOperation::NeedsHuman,
            ),
        )
        .unwrap()]);
        let mut output = Vec::new();

        let plan = dry_run(&catalog, &desired, &mut output)
            .unwrap_or_else(|error| panic!("case {index} must remain actionable: {error}"));

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let entries = plan.entries().collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].operation(), PlanOperation::NeedsHuman);
        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.contains("!"));
        assert!(rendered.contains(INSTRUCTIONS));
        assert!(!rendered.contains("[sudo]"));
        assert!(!rendered.contains("[admin]"));
        assert!(!rendered.contains("+ "));
        assert!(!rendered.contains("~ "));
        assert!(!rendered.contains("= "));
    }
}

#[test]
fn badges_and_first_seen_component_groups_are_exact_and_special_lines_stay_typed() {
    let catalog = test_support::catalog(vec![
        test_support::TestProbe::fixed(
            "tool.root",
            ProbeStatus::Present {
                version: None,
                healthy: true,
            },
            Arc::new(AtomicUsize::new(0)),
        ),
        test_support::TestProbe::fixed(
            "tool.admin",
            ProbeStatus::Present {
                version: None,
                healthy: true,
            },
            Arc::new(AtomicUsize::new(0)),
        ),
        test_support::TestProbe::fixed(
            "tool.none",
            ProbeStatus::Present {
                version: None,
                healthy: true,
            },
            Arc::new(AtomicUsize::new(0)),
        ),
        test_support::TestProbe::fixed(
            "tool.human",
            ProbeStatus::Absent,
            Arc::new(AtomicUsize::new(0)),
        ),
        test_support::TestProbe::fixed(
            "tool.skip",
            ProbeStatus::Absent,
            Arc::new(AtomicUsize::new(0)),
        ),
        test_support::TestProbe::fixed(
            "tool.remove",
            ProbeStatus::Present {
                version: None,
                healthy: true,
            },
            Arc::new(AtomicUsize::new(0)),
        ),
    ]);
    let desired = DesiredState::new(vec![
        converge_with_done(
            "tool.root",
            "first",
            "first.root",
            "root line",
            Privilege::Root,
        ),
        converge_with_done(
            "tool.admin",
            "second",
            "second.admin",
            "admin line",
            Privilege::Admin,
        ),
        converge_with_done(
            "tool.none",
            "first",
            "first.none",
            "plain line",
            Privilege::None,
        ),
        DesiredChange::needs_human(
            id("tool.human"),
            "special",
            action(
                "tool.human",
                "special.human",
                "authenticate in browser",
                Privilege::None,
                PlanOperation::NeedsHuman,
            ),
        )
        .unwrap(),
        DesiredChange::skipped(
            id("tool.skip"),
            "special",
            action(
                "tool.skip",
                "special.skip",
                "enable with configuration",
                Privilege::None,
                PlanOperation::Skipped,
            ),
        )
        .unwrap(),
        DesiredChange::remove(
            id("tool.remove"),
            "special",
            action(
                "tool.remove",
                "special.remove",
                "remove old component",
                Privilege::Admin,
                PlanOperation::Remove,
            ),
        )
        .unwrap(),
    ]);
    let plan = SetupPlan::compute(&catalog.observe(), &desired).unwrap();
    let mut rendered = Vec::new();

    render_dry_run(&plan, &mut rendered).unwrap();

    assert_eq!(
        String::from_utf8(rendered).unwrap(),
        "first:\n  ✓ root line [sudo]\n  ✓ plain line\nsecond:\n  ✓ admin line [admin]\nspecial:\n  ! authenticate in browser\n  . enable with configuration\n  - remove old component [admin]\n"
    );
}

#[test]
fn cross_linked_action_subjects_are_rejected_without_exposing_the_foreign_subject() {
    let foreign = action(
        "tool.foreign",
        "test.foreign",
        "foreign action",
        Privilege::None,
        PlanOperation::Create,
    );
    let error = DesiredChange::converge(
        id("tool.local"),
        "local",
        foreign,
        action(
            "tool.local",
            "test.repair",
            "repair local",
            Privilege::None,
            PlanOperation::Reconfigure,
        ),
        action(
            "tool.local",
            "test.done",
            "local is healthy",
            Privilege::None,
            PlanOperation::Done,
        ),
    )
    .unwrap_err();

    assert_eq!(error, PlanError::InvalidCrossLink);
    assert!(!error.to_string().contains("tool.foreign"));
}
