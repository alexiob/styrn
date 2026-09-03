use super::{
    ActionCheck, ActionDescription, ActionError, ActionName, ActionParameters,
    DedicatedAccountPrerequisiteParameters, HumanInstructions, NeedsHuman,
};
use crate::platform::{DedicatedAccountSpec, InstallationScope};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

const DESCRIPTION: &str = "Adopt the selected dedicated worker account";
const INSTRUCTIONS: &str = "Provision the selected local account with the required dedicated-worker posture, then rerun setup. Current-user mode remains active until adoption completes.";

pub(crate) struct DedicatedAccountPrerequisite {
    parameters: DedicatedAccountPrerequisiteParameters,
    description: ActionDescription,
    state: DedicatedAccountPrerequisiteState,
}

enum DedicatedAccountPrerequisiteState {
    Ready(crate::platform::DedicatedAccountHandle),
    NeedsHuman(NeedsHuman),
}

#[derive(Clone)]
pub(crate) struct DedicatedAccountReady {
    original_operator: crate::platform::WorkerPrincipal,
    target: crate::platform::DedicatedAccountHandle,
    selector: Box<str>,
}

impl DedicatedAccountReady {
    pub(super) fn original_operator(&self) -> &crate::platform::WorkerPrincipal {
        &self.original_operator
    }

    pub(super) fn selector(&self) -> &str {
        &self.selector
    }

    pub(super) fn reverify_target<Output>(
        &self,
        bind: impl for<'binding> FnOnce(&'binding crate::platform::WorkerPrincipal) -> Output,
    ) -> Result<Output, crate::platform::DedicatedAccountIssue> {
        let authority = super::dedicated_account_action_authority();
        self.target.reverify_and_bind_for_action(&authority, bind)
    }

    pub(in crate::setup) fn manifest_candidate(
        &self,
        base: &crate::manifest::MachineManifestDraft,
    ) -> Result<crate::manifest::DedicatedWorkerManifestCandidate, crate::manifest::ManifestError>
    {
        crate::manifest::DedicatedWorkerManifestCandidate::derive(base, &self.target)
    }

    #[cfg(test)]
    pub(super) fn manifest_candidate_with_layout_for_test(
        &self,
        base: &crate::manifest::MachineManifestDraft,
        layout: &crate::platform::WorkerDirectoryLayout,
    ) -> Result<crate::manifest::DedicatedWorkerManifestCandidate, crate::manifest::ManifestError>
    {
        crate::manifest::DedicatedWorkerManifestCandidate::derive_with_layout_for_test(
            base,
            &self.target,
            layout,
        )
    }
}

pub(crate) struct DedicatedAccountSelection {
    action: super::Action,
    ready: Option<DedicatedAccountReady>,
}

impl DedicatedAccountSelection {
    pub(crate) fn action(&self) -> &super::Action {
        &self.action
    }

    pub(in crate::setup) fn into_parts(self) -> (super::Action, Option<DedicatedAccountReady>) {
        (self.action, self.ready)
    }

    #[cfg(test)]
    fn ready(&self) -> Option<&DedicatedAccountReady> {
        self.ready.as_ref()
    }
}

pub(in crate::setup) fn dedicated_account_prerequisite(
    spec: DedicatedAccountSpec,
) -> Result<super::Action, ActionError> {
    DedicatedAccountPrerequisite::new(spec).map(super::Action::DedicatedAccountPrerequisite)
}

impl DedicatedAccountPrerequisite {
    pub(super) fn new(spec: DedicatedAccountSpec) -> Result<Self, ActionError> {
        let action_id = dedicated_account_prerequisite_action_id(&spec)?;
        Ok(Self {
            parameters: DedicatedAccountPrerequisiteParameters {
                action_id,
                target_scope: InstallationScope::System,
                selector: spec.name().into(),
            },
            description: ActionDescription::new(DESCRIPTION)?,
            state: DedicatedAccountPrerequisiteState::NeedsHuman(NeedsHuman::new(
                HumanInstructions::new(INSTRUCTIONS)?,
                None,
            )),
        })
    }

    fn ready(
        spec: DedicatedAccountSpec,
        handle: crate::platform::DedicatedAccountHandle,
    ) -> Result<Self, ActionError> {
        let mut prerequisite = Self::new(spec)?;
        prerequisite.state = DedicatedAccountPrerequisiteState::Ready(handle);
        Ok(prerequisite)
    }

    pub(in crate::setup) fn action_id(&self) -> &ActionName {
        self.parameters.action_id()
    }

    pub(in crate::setup) fn selector(&self) -> &str {
        self.parameters.selector()
    }

    pub(in crate::setup) fn target_scope(&self) -> InstallationScope {
        self.parameters.target_scope()
    }

    pub(super) fn name(&self) -> &ActionName {
        self.parameters.action_id()
    }

    pub(super) fn parameters(&self) -> ActionParameters {
        ActionParameters::DedicatedAccountPrerequisite(self.parameters.clone())
    }

    pub(super) fn check(&self) -> ActionCheck {
        match &self.state {
            DedicatedAccountPrerequisiteState::Ready(handle) => {
                let authority = super::dedicated_account_action_authority();
                match handle.reverify_for_adoption(&authority) {
                    Ok(()) => ActionCheck::Done,
                    Err(_) => ActionCheck::NeedsHuman(static_needs_human()),
                }
            }
            DedicatedAccountPrerequisiteState::NeedsHuman(needs_human) => {
                ActionCheck::NeedsHuman(needs_human.clone())
            }
        }
    }

    pub(super) fn privilege(&self) -> super::Privilege {
        super::Privilege::None
    }

    pub(super) fn plan_operation(&self) -> super::PlanOperation {
        match self.state {
            DedicatedAccountPrerequisiteState::Ready(_) => super::PlanOperation::Done,
            DedicatedAccountPrerequisiteState::NeedsHuman(_) => super::PlanOperation::NeedsHuman,
        }
    }

    pub(super) fn description(&self) -> &ActionDescription {
        &self.description
    }
}

fn static_needs_human() -> NeedsHuman {
    NeedsHuman::new(
        HumanInstructions::new(INSTRUCTIONS).expect("static dedicated instructions are valid"),
        None,
    )
}

#[allow(dead_code)] // T0.20 wires configured selection into setup plan assembly.
pub(in crate::setup) fn select_dedicated_account(
    context: &crate::platform::SetupExecutionContext,
    spec: DedicatedAccountSpec,
) -> Result<DedicatedAccountSelection, ActionError> {
    let selector = spec.name().to_owned();
    let observation = crate::platform::inspect_dedicated_account(spec);
    select_dedicated_account_observation(
        context,
        DedicatedAccountSpec::new(&selector).map_err(|_| ActionError::InvalidActionName)?,
        observation,
    )
}

pub(super) fn select_dedicated_account_observation(
    context: &crate::platform::SetupExecutionContext,
    spec: DedicatedAccountSpec,
    observation: crate::platform::DedicatedAccountObservation,
) -> Result<DedicatedAccountSelection, ActionError> {
    let operator = context.original_principal();
    if operator.account_policy() != crate::platform::WorkerAccountPolicy::CurrentUser
        || crate::platform::verify_worker_principal(operator).is_err()
    {
        return Err(ActionError::InvalidDedicatedAccountSelection);
    }
    let selector = spec.name().to_owned();
    let (component, ready) = match observation {
        crate::platform::DedicatedAccountObservation::PresentHealthy(handle) => {
            let authority = super::dedicated_account_action_authority();
            if handle.reverify_for_adoption(&authority).is_ok() {
                (
                    DedicatedAccountPrerequisite::ready(spec, handle.clone())?,
                    Some(DedicatedAccountReady {
                        original_operator: operator.clone(),
                        target: handle,
                        selector: selector.into(),
                    }),
                )
            } else {
                (DedicatedAccountPrerequisite::new(spec)?, None)
            }
        }
        crate::platform::DedicatedAccountObservation::Absent
        | crate::platform::DedicatedAccountObservation::PresentBroken(_)
        | crate::platform::DedicatedAccountObservation::Unknowable(_) => {
            (DedicatedAccountPrerequisite::new(spec)?, None)
        }
    };
    Ok(DedicatedAccountSelection {
        action: super::Action::DedicatedAccountPrerequisite(component),
        ready,
    })
}

pub(in crate::setup) fn dedicated_account_prerequisite_action_id(
    spec: &DedicatedAccountSpec,
) -> Result<ActionName, ActionError> {
    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(spec.name().as_bytes()) {
        write!(&mut digest, "{byte:02x}").expect("writing hexadecimal to a String cannot fail");
    }
    ActionName::parse(&format!("identity.account.dedicated.sha256-{digest}"))
}

#[cfg(test)]
mod tests {
    use super::super::{ActionCheck, ActionParameters, ApplyOutcome, PlanOperation, Privilege};
    use crate::platform::{DedicatedAccountSpec, InstallationScope};

    fn dedicated_principal(name: &str) -> crate::platform::WorkerPrincipal {
        let current = crate::platform::resolve_current_worker_principal().unwrap();
        crate::platform::WorkerPrincipal::new(
            current.principal_kind(),
            current.principal_id(),
            name,
            crate::platform::WorkerAccountPolicy::Dedicated,
        )
        .unwrap()
    }

    #[test]
    fn dedicated_account_prerequisite_uses_a_selector_bound_closed_pending_action() {
        let prerequisite = super::DedicatedAccountPrerequisite::new(
            DedicatedAccountSpec::new("build-agent").unwrap(),
        )
        .unwrap();

        assert_eq!(
            prerequisite.name().as_str(),
            "identity.account.dedicated.sha256-7f81291a9c35cb94e74c8794e4c1ea1c0966b92fc67a72490ef0df956320a394"
        );
        let ActionParameters::DedicatedAccountPrerequisite(parameters) = prerequisite.parameters()
        else {
            panic!("dedicated prerequisite must retain typed receipt parameters");
        };
        assert_eq!(parameters.target_scope(), InstallationScope::System);
        assert_eq!(parameters.selector(), "build-agent");
        assert_eq!(prerequisite.privilege(), Privilege::None);
        assert_eq!(prerequisite.plan_operation(), PlanOperation::NeedsHuman);
        let ActionCheck::NeedsHuman(pending) = prerequisite.check() else {
            panic!("unresolved dedicated account must remain human-owned");
        };
        assert_eq!(
            pending.instructions().as_str(),
            "Provision the selected local account with the required dedicated-worker posture, then rerun setup. Current-user mode remains active until adoption completes."
        );
        assert!(pending.fragment().is_none());
    }

    #[test]
    fn dedicated_account_prerequisite_cannot_prepare_apply_or_collide_across_selectors() {
        let mut first = super::dedicated_account_prerequisite(
            DedicatedAccountSpec::new("build-agent").unwrap(),
        )
        .unwrap();
        let second = super::dedicated_account_prerequisite(
            DedicatedAccountSpec::new("release-agent").unwrap(),
        )
        .unwrap();

        assert_ne!(first.name(), second.name());
        let ApplyOutcome::NeedsHuman(pending) = first.apply().unwrap() else {
            panic!("the prerequisite must never execute or become ownership");
        };
        assert!(pending.fragment().is_none());
        assert!(first.prepare().is_err());
    }

    #[test]
    fn dedicated_account_adoption_releases_ready_only_after_fresh_bound_reverification() {
        let operator = crate::platform::resolve_current_worker_principal().unwrap();
        let context = crate::platform::SetupExecutionContext::new_for_test(
            crate::platform::SetupHostPrivilege::Ordinary,
            operator.clone(),
        );
        let target = dedicated_principal("build-agent");
        let healthy = crate::platform::dedicated_account_observation_for_action_test(
            DedicatedAccountSpec::new("build-agent").unwrap(),
            crate::platform::TestDedicatedAccountObservation::Healthy(target.clone()),
            crate::platform::TestDedicatedAccountObservation::Healthy(target),
        );

        let selection = super::select_dedicated_account_observation(
            &context,
            DedicatedAccountSpec::new("build-agent").unwrap(),
            healthy,
        )
        .unwrap();

        assert!(selection.ready().is_some());
        assert_eq!(selection.ready().unwrap().original_operator, operator);
        assert_eq!(selection.action().check().unwrap(), ActionCheck::Done);

        let drifted = crate::platform::dedicated_account_observation_for_action_test(
            DedicatedAccountSpec::new("build-agent").unwrap(),
            crate::platform::TestDedicatedAccountObservation::Healthy(dedicated_principal(
                "build-agent",
            )),
            crate::platform::TestDedicatedAccountObservation::Absent,
        );
        let drifted = super::select_dedicated_account_observation(
            &context,
            DedicatedAccountSpec::new("build-agent").unwrap(),
            drifted,
        )
        .unwrap();
        assert!(drifted.ready().is_none());
        assert!(matches!(
            drifted.action().check().unwrap(),
            ActionCheck::NeedsHuman(_)
        ));
    }

    #[test]
    fn dedicated_account_adoption_maps_every_unready_state_to_the_same_static_fallback() {
        let operator = crate::platform::resolve_current_worker_principal().unwrap();
        let context = crate::platform::SetupExecutionContext::new_for_test(
            crate::platform::SetupHostPrivilege::Ordinary,
            operator,
        );
        for observation in [
            crate::platform::TestDedicatedAccountObservation::Absent,
            crate::platform::TestDedicatedAccountObservation::Broken,
            crate::platform::TestDedicatedAccountObservation::Unknowable,
        ] {
            let observed = crate::platform::dedicated_account_observation_for_action_test(
                DedicatedAccountSpec::new("build-agent").unwrap(),
                observation,
                crate::platform::TestDedicatedAccountObservation::Absent,
            );
            let selection = super::select_dedicated_account_observation(
                &context,
                DedicatedAccountSpec::new("build-agent").unwrap(),
                observed,
            )
            .unwrap();
            assert!(selection.ready().is_none());
            let ActionCheck::NeedsHuman(pending) = selection.action().check().unwrap() else {
                panic!("unready selection escaped its fallback prerequisite");
            };
            assert_eq!(pending.instructions().as_str(), super::INSTRUCTIONS);
            assert!(pending.fragment().is_none());
            assert_eq!(selection.action().privilege(), Privilege::None);
        }
    }

    #[test]
    fn dedicated_account_ready_is_a_noop_and_never_creates_an_account_receipt() {
        let operator = crate::platform::resolve_current_worker_principal().unwrap();
        let context = crate::platform::SetupExecutionContext::new_for_test(
            crate::platform::SetupHostPrivilege::Ordinary,
            operator,
        );
        let target = dedicated_principal("build-agent");
        let observed = crate::platform::dedicated_account_observation_for_action_test(
            DedicatedAccountSpec::new("build-agent").unwrap(),
            crate::platform::TestDedicatedAccountObservation::Healthy(target.clone()),
            crate::platform::TestDedicatedAccountObservation::Healthy(target),
        );
        let selection = super::select_dedicated_account_observation(
            &context,
            DedicatedAccountSpec::new("build-agent").unwrap(),
            observed,
        )
        .unwrap();
        let (action, ready) = selection.into_parts();
        assert!(ready.is_some());

        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("styrn-ready-no-receipt-{}", uuid::Uuid::now_v7()));
        let state = root.join("styrn");
        std::fs::create_dir_all(&state).unwrap();
        let current = crate::platform::resolve_current_worker_principal().unwrap();
        crate::platform::harden_manifest_directory(
            &root,
            crate::platform::ManifestOwner::User,
            &current,
        )
        .unwrap();
        crate::platform::harden_manifest_directory(
            &state,
            crate::platform::ManifestOwner::User,
            &current,
        )
        .unwrap();
        let receipt_path = state.join("receipt.json");
        let store = crate::setup::receipt::ReceiptStore::new_user_for_test(&receipt_path);
        let report = super::super::apply_plan_with_journal(
            &mut [action],
            &store,
            &mut crate::setup::receipt::ReceiptMetadataSource::for_test([]),
        )
        .unwrap();

        assert_eq!(report.noop_count(), 1);
        assert_eq!(report.pending_count(), 0);
        assert_eq!(store.read_snapshot().unwrap().entry_count(), 0);
        assert!(!receipt_path.exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
