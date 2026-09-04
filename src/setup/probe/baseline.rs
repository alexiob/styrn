use super::{
    worker_probe_only, FindingSeverity, ObservedTailscaleMode, ObservedTailscalePosture,
    ProbeCatalog, ProbeCatalogError, ProbeDescriptorSpec, ProbeFailure, ProbeId, ProbeStatus,
    WorkerProbe,
};
use crate::setup::{
    action::{PlanOperation, Privilege},
    plan::{DesiredAction, DesiredChange, DesiredState},
    EffectiveRootlessSetup,
};

struct BaselineProbe {
    descriptor: ProbeDescriptorSpec,
    kind: crate::platform::BaselineProbeKind,
    authorized_public_keys: Vec<String>,
    tailscale_mode: String,
}

impl worker_probe_only::Sealed for BaselineProbe {}

impl WorkerProbe for BaselineProbe {
    fn descriptor(&self) -> &ProbeDescriptorSpec {
        &self.descriptor
    }

    fn observe(&self) -> Result<ProbeStatus, ProbeFailure> {
        Ok(
            match crate::platform::baseline_probe_snapshot(
                self.kind,
                &self.authorized_public_keys,
                &self.tailscale_mode,
            ) {
                crate::platform::BaselineProbeSnapshot::Absent => ProbeStatus::Absent,
                crate::platform::BaselineProbeSnapshot::Present { version, healthy } => {
                    ProbeStatus::Present { version, healthy }
                }
                crate::platform::BaselineProbeSnapshot::TailscalePresent {
                    version,
                    healthy,
                    posture,
                } => ProbeStatus::TailscalePresent {
                    version,
                    healthy,
                    posture: ObservedTailscalePosture {
                        mode: match posture.mode {
                            crate::platform::BaselineTailscaleMode::Gui => {
                                ObservedTailscaleMode::Gui
                            }
                            crate::platform::BaselineTailscaleMode::Tailscaled => {
                                ObservedTailscaleMode::Tailscaled
                            }
                            crate::platform::BaselineTailscaleMode::Service => {
                                ObservedTailscaleMode::Service
                            }
                        },
                        persistent: posture.persistent,
                        unattended: posture.unattended,
                    },
                },
                crate::platform::BaselineProbeSnapshot::Broken => ProbeStatus::Broken {
                    reason: "baseline capability state is broken".to_owned(),
                },
                crate::platform::BaselineProbeSnapshot::Unknowable => ProbeStatus::Unknowable {
                    reason: "baseline readiness could not be proven".to_owned(),
                },
            },
        )
    }
}

pub(in crate::setup) fn production_rootless_catalog(
    effective: &EffectiveRootlessSetup,
) -> Result<ProbeCatalog, ProbeCatalogError> {
    let probes = effective
        .selected_component_names()
        .map(|component| {
            Box::new(BaselineProbe {
                descriptor: descriptor(component),
                kind: probe_kind(component),
                authorized_public_keys: effective.authorized_public_keys().to_vec(),
                tailscale_mode: effective.requested_tailscale_mode().to_owned(),
            }) as Box<dyn WorkerProbe>
        })
        .collect();
    ProbeCatalog::new(probes)
}

pub(in crate::setup) fn rootless_baseline_desired_state(
    effective: &EffectiveRootlessSetup,
) -> Result<DesiredState, crate::setup::plan::PlanError> {
    effective
        .selected_component_names()
        .map(|component| {
            let subject = probe_id(component);
            DesiredChange::adopt_or_defer(
                subject.clone(),
                component,
                DesiredAction::new(
                    subject.clone(),
                    &format!("baseline.{component}.adopted"),
                    "Existing host capability is ready and remains externally owned.",
                    Privilege::None,
                    PlanOperation::Done,
                )?,
                DesiredAction::new(
                    subject,
                    &format!("baseline.{component}.pending"),
                    pending_instructions(component),
                    Privilege::None,
                    PlanOperation::NeedsHuman,
                )?,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map(DesiredState::new)
}

fn pending_instructions(component: &str) -> &'static str {
    match component {
        "ssh-server" => "Enable the native SSH server with public-key authentication and a valid current-user authorized_keys file, then retry setup.",
        "tailscale" => "Install Tailscale, start its local backend, sign in outside Styrn, then retry setup.",
        "git" => "Install or repair Git so git --version succeeds, then retry setup.",
        "styrnd" => "This release does not include the styrnd worker service; install a future supported release, then retry setup.",
        "sleep-policy" => "Disable ordinary automatic sleep with native system settings, then retry setup.",
        "rust" | "sccache" | "herdr" | "codex" | "claude" | "rdp" | "cockpit" => {
            "This selected component is not implemented by rootless setup yet; configure it outside Styrn, then retry setup."
        }
        _ => unreachable!("effective setup contains only closed components"),
    }
}

fn descriptor(component: &str) -> ProbeDescriptorSpec {
    ProbeDescriptorSpec::new(
        probe_id(component),
        format!("{component} baseline readiness"),
        FindingSeverity::Warning,
        None,
    )
    .expect("closed baseline descriptors must be valid")
}

fn probe_id(component: &str) -> ProbeId {
    ProbeId::parse(match component {
        "ssh-server" => "service.sshd",
        "tailscale" => "network.tailscale",
        "git" => "tool.git",
        "rust" => "tool.rust",
        "sccache" => "tool.sccache",
        "herdr" => "tool.herdr",
        "codex" => "tool.codex",
        "claude" => "tool.claude",
        "styrnd" => "service.styrnd",
        "sleep-policy" => "policy.sleep",
        "rdp" => "service.rdp",
        "cockpit" => "service.cockpit",
        _ => unreachable!("effective setup contains only closed components"),
    })
    .expect("closed baseline probe IDs must be valid")
}

fn probe_kind(component: &str) -> crate::platform::BaselineProbeKind {
    use crate::platform::BaselineProbeKind;
    match component {
        "ssh-server" => BaselineProbeKind::SshServer,
        "tailscale" => BaselineProbeKind::Tailscale,
        "git" => BaselineProbeKind::Git,
        "styrnd" => BaselineProbeKind::Styrnd,
        "sleep-policy" => BaselineProbeKind::SleepPolicy,
        "rust" | "sccache" | "herdr" | "codex" | "claude" | "rdp" | "cockpit" => {
            BaselineProbeKind::Deferred
        }
        _ => unreachable!("effective setup contains only closed components"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{self, BaselineProbeKind, BaselineProbeSnapshot};
    use crate::setup::{action::ActionCheck, plan::SetupPlan};

    #[test]
    fn rootless_baseline_catalog_is_closed_unique_and_canonical_ordered() {
        let effective = crate::setup::config::effective_from_interactive_answers(
            "worker".to_owned(),
            Some("rust,sccache,herdr,codex,claude,rdp,cockpit"),
            None,
        )
        .unwrap();

        let catalog = production_rootless_catalog(&effective).unwrap();
        let ids = catalog
            .descriptors()
            .map(|descriptor| descriptor.id().as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            ids,
            [
                "service.sshd",
                "network.tailscale",
                "tool.git",
                "tool.rust",
                "tool.sccache",
                "tool.herdr",
                "tool.codex",
                "tool.claude",
                "service.styrnd",
                "policy.sleep",
                "service.rdp",
                "service.cockpit",
            ]
        );
    }

    #[test]
    fn healthy_present_baseline_capabilities_are_done_privilege_none_and_unowned() {
        platform::set_baseline_probe_snapshots_for_test([
            (
                BaselineProbeKind::SshServer,
                BaselineProbeSnapshot::Present {
                    version: None,
                    healthy: true,
                },
            ),
            (
                BaselineProbeKind::Tailscale,
                BaselineProbeSnapshot::Present {
                    version: Some("1.90.0".to_owned()),
                    healthy: true,
                },
            ),
            (
                BaselineProbeKind::Git,
                BaselineProbeSnapshot::Present {
                    version: Some("2.51.0".to_owned()),
                    healthy: true,
                },
            ),
            (
                BaselineProbeKind::SleepPolicy,
                BaselineProbeSnapshot::Present {
                    version: None,
                    healthy: true,
                },
            ),
        ]);
        let effective = crate::setup::config::effective_from_interactive_answers(
            "worker".to_owned(),
            None,
            None,
        )
        .unwrap();
        let catalog = production_rootless_catalog(&effective).unwrap();
        let observed = catalog.observe();
        let desired = rootless_baseline_desired_state(&effective).unwrap();
        let plan = SetupPlan::compute(&observed, &desired).unwrap();
        let entries = plan.entries().collect::<Vec<_>>();

        assert_eq!(entries.len(), 5);
        for entry in &entries[..3] {
            assert_eq!(entry.operation(), PlanOperation::Done);
            assert_eq!(entry.action().privilege(), Privilege::None);
            assert_eq!(entry.action().check().unwrap(), ActionCheck::Done);
        }
        assert_eq!(entries[3].operation(), PlanOperation::NeedsHuman);
        assert_eq!(entries[4].operation(), PlanOperation::Done);
        assert!(matches!(
            entries[3].action().check().unwrap(),
            ActionCheck::NeedsHuman(_)
        ));
        assert_eq!(entries[4].action().check().unwrap(), ActionCheck::Done);
        platform::clear_baseline_probe_snapshots_for_test();
    }

    #[test]
    fn absent_broken_unhealthy_and_unknowable_baseline_capabilities_are_static_pending() {
        platform::set_baseline_probe_snapshots_for_test([
            (BaselineProbeKind::SshServer, BaselineProbeSnapshot::Absent),
            (
                BaselineProbeKind::Tailscale,
                BaselineProbeSnapshot::Present {
                    version: None,
                    healthy: false,
                },
            ),
            (BaselineProbeKind::Git, BaselineProbeSnapshot::Broken),
            (
                BaselineProbeKind::SleepPolicy,
                BaselineProbeSnapshot::Unknowable,
            ),
        ]);
        let effective = crate::setup::config::effective_from_interactive_answers(
            "worker".to_owned(),
            Some("rust,sccache,herdr,codex,claude,rdp,cockpit"),
            None,
        )
        .unwrap();
        let plan = SetupPlan::compute(
            &production_rootless_catalog(&effective).unwrap().observe(),
            &rootless_baseline_desired_state(&effective).unwrap(),
        )
        .unwrap();

        assert_eq!(plan.entries().len(), 12);
        for entry in plan.entries() {
            assert_eq!(entry.operation(), PlanOperation::NeedsHuman);
            assert_eq!(entry.action().privilege(), Privilege::None);
            let ActionCheck::NeedsHuman(needs_human) = entry.action().check().unwrap() else {
                panic!("non-adoptable baseline capability was not pending")
            };
            assert!(needs_human.fragment().is_none());
        }
        platform::clear_baseline_probe_snapshots_for_test();
    }

    #[test]
    fn styrnd_and_selected_unimplemented_components_remain_truthful_pending() {
        let effective = crate::setup::config::effective_from_interactive_answers(
            "worker".to_owned(),
            Some("rust,sccache,herdr,codex,claude,rdp,cockpit"),
            None,
        )
        .unwrap();
        let observed = production_rootless_catalog(&effective).unwrap().observe();

        for subject in [
            "tool.rust",
            "tool.sccache",
            "tool.herdr",
            "tool.codex",
            "tool.claude",
            "service.styrnd",
            "service.rdp",
            "service.cockpit",
        ] {
            let status = observed.get(&probe_id_for_test(subject)).unwrap().status();
            if subject == "service.styrnd" {
                assert!(matches!(status, ProbeStatus::Absent));
            } else {
                assert!(matches!(status, ProbeStatus::Unknowable { .. }));
            }
        }
    }

    fn probe_id_for_test(value: &str) -> ProbeId {
        ProbeId::parse(value).unwrap()
    }
}
