//! Deterministic setup diffing and read-only plan rendering.
//!
//! This module consumes the canonical worker-local observations; it does not
//! register probes, execute actions, elevate, or journal receipts.

use super::{
    action::{Action, ActionCheck, ActionDescription, ActionError, ActionName, Privilege},
    probe::{ProbeCatalog, ProbeId, ProbeStatus},
    ObservedState,
};
use std::{collections::HashSet, fmt, io::Write};
use thiserror::Error;

#[cfg(plan_pending_forge_fixture)]
#[path = "hostile_pending.rs"]
mod hostile_pending;

#[cfg(any(
    plan_pending_publication_forge_fixture,
    plan_pending_authority_forge_fixture
))]
#[path = "hostile_pending_publication.rs"]
mod hostile_pending_publication;

#[cfg(plan_pending_projection_fixture)]
#[path = "hostile_pending_projection.rs"]
mod hostile_pending_projection;

#[cfg(plan_completed_execution_construct_fixture)]
#[path = "hostile_completed_execution_construct.rs"]
mod hostile_completed_execution_construct;

#[cfg(any(
    plan_completed_execution_mutate_fixture,
    plan_completed_execution_clone_fixture,
    plan_completed_execution_serialize_fixture
))]
#[path = "hostile_completed_execution_mutate.rs"]
mod hostile_completed_execution_mutate;

pub(crate) use super::action::PlanOperation;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DesiredState {
    changes: Vec<DesiredChange>,
}

impl DesiredState {
    pub(crate) fn new(changes: Vec<DesiredChange>) -> Self {
        Self { changes }
    }

    fn changes(&self) -> &[DesiredChange] {
        &self.changes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DesiredAction {
    subject: ProbeId,
    name: ActionName,
    description: ActionDescription,
    privilege: Privilege,
    operation: PlanOperation,
}

impl DesiredAction {
    pub(crate) fn new(
        subject: ProbeId,
        name: &str,
        description: &str,
        privilege: Privilege,
        operation: PlanOperation,
    ) -> Result<Self, PlanError> {
        Ok(Self {
            subject,
            name: ActionName::parse(name).map_err(|_| PlanError::InvalidAction)?,
            description: ActionDescription::new(description)
                .map_err(|_| PlanError::InvalidAction)?,
            privilege,
            operation,
        })
    }

    fn subject(&self) -> &ProbeId {
        &self.subject
    }

    fn into_action(self) -> Action {
        Action::planned(self.name, self.description, self.privilege, self.operation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DesiredChange {
    subject: ProbeId,
    component: ComponentName,
    behavior: DesiredBehavior,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DesiredBehavior {
    Converge {
        create: DesiredAction,
        repair: DesiredAction,
        done: DesiredAction,
    },
    Exceptional {
        action: DesiredAction,
        required_observation: ExceptionalObservation,
    },
    AdoptOrDefer {
        done: DesiredAction,
        needs_human: DesiredAction,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExceptionalObservation {
    Absent,
    HumanRequired,
    Healthy,
}

impl DesiredChange {
    /// Adopts an already healthy capability without claiming receipt ownership,
    /// or records static human work for every state that cannot be adopted.
    pub(crate) fn adopt_or_defer(
        subject: ProbeId,
        component: &str,
        done: DesiredAction,
        needs_human: DesiredAction,
    ) -> Result<Self, PlanError> {
        if [&done, &needs_human]
            .iter()
            .any(|action| action.subject() != &subject || action.privilege != Privilege::None)
            || done.operation != PlanOperation::Done
            || needs_human.operation != PlanOperation::NeedsHuman
        {
            return Err(PlanError::InvalidCrossLink);
        }
        Ok(Self {
            subject,
            component: ComponentName::parse(component)?,
            behavior: DesiredBehavior::AdoptOrDefer { done, needs_human },
        })
    }

    pub(crate) fn converge(
        subject: ProbeId,
        component: &str,
        create: DesiredAction,
        repair: DesiredAction,
        done: DesiredAction,
    ) -> Result<Self, PlanError> {
        let component = ComponentName::parse(component)?;
        if [&create, &repair, &done]
            .iter()
            .any(|action| action.subject() != &subject)
            || create.operation != PlanOperation::Create
            || repair.operation != PlanOperation::Reconfigure
            || done.operation != PlanOperation::Done
        {
            return Err(PlanError::InvalidCrossLink);
        }
        Ok(Self {
            subject,
            component,
            behavior: DesiredBehavior::Converge {
                create,
                repair,
                done,
            },
        })
    }

    /// A missing, broken, or unobservable capability whose next step cannot be
    /// automated and has explicit safe human instructions.
    pub(crate) fn needs_human(
        subject: ProbeId,
        component: &str,
        action: DesiredAction,
    ) -> Result<Self, PlanError> {
        Self::exceptional(
            subject,
            component,
            action,
            PlanOperation::NeedsHuman,
            ExceptionalObservation::HumanRequired,
        )
    }

    /// An absent optional capability deliberately excluded from this setup.
    pub(crate) fn skipped(
        subject: ProbeId,
        component: &str,
        action: DesiredAction,
    ) -> Result<Self, PlanError> {
        Self::exceptional(
            subject,
            component,
            action,
            PlanOperation::Skipped,
            ExceptionalObservation::Absent,
        )
    }

    /// A healthy present capability selected for removal.
    pub(crate) fn remove(
        subject: ProbeId,
        component: &str,
        action: DesiredAction,
    ) -> Result<Self, PlanError> {
        Self::exceptional(
            subject,
            component,
            action,
            PlanOperation::Remove,
            ExceptionalObservation::Healthy,
        )
    }

    fn exceptional(
        subject: ProbeId,
        component: &str,
        action: DesiredAction,
        expected_operation: PlanOperation,
        required_observation: ExceptionalObservation,
    ) -> Result<Self, PlanError> {
        if action.subject() != &subject || action.operation != expected_operation {
            return Err(PlanError::InvalidCrossLink);
        }
        Ok(Self {
            subject,
            component: ComponentName::parse(component)?,
            behavior: DesiredBehavior::Exceptional {
                action,
                required_observation,
            },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ComponentName(String);

impl ComponentName {
    fn parse(value: &str) -> Result<Self, PlanError> {
        if super::validate_probe_static_text(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(PlanError::InvalidComponent)
        }
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum PlanError {
    #[error("desired setup action is invalid")]
    InvalidAction,
    #[error("desired setup component is invalid")]
    InvalidComponent,
    #[error("desired setup action does not match its observed subject")]
    InvalidCrossLink,
    #[error("desired setup subjects must be unique")]
    DuplicateDesiredSubject,
    #[error("desired setup subject has no observation")]
    MissingObservation,
    #[error("setup plan is blocked because an observation is unknowable")]
    UnknowableObservation,
    #[error("exceptional setup plan line does not match the observed state")]
    ExceptionalObservationMismatch,
}

#[derive(Debug, Error)]
pub(crate) enum DryRunError {
    #[error(transparent)]
    Plan(#[from] PlanError),
    #[error("a planned action could not be checked")]
    Action(#[source] ActionError),
    #[error("could not write dry-run output")]
    Write(#[source] std::io::Error),
}

pub(crate) struct SetupPlan {
    entries: Vec<PlanEntry>,
}

impl fmt::Debug for SetupPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SetupPlan")
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

impl SetupPlan {
    pub(crate) fn compute(
        observed: &ObservedState,
        desired: &DesiredState,
    ) -> Result<Self, PlanError> {
        let mut subjects = HashSet::with_capacity(desired.changes().len());
        for change in desired.changes() {
            if !subjects.insert(change.subject.clone()) {
                return Err(PlanError::DuplicateDesiredSubject);
            }
            let Some(observation) = observed.get(&change.subject) else {
                return Err(PlanError::MissingObservation);
            };
            if matches!(observation.status(), ProbeStatus::Unknowable { .. })
                && !matches!(
                    &change.behavior,
                    DesiredBehavior::Exceptional {
                        required_observation: ExceptionalObservation::HumanRequired,
                        ..
                    } | DesiredBehavior::AdoptOrDefer { .. }
                )
            {
                return Err(PlanError::UnknowableObservation);
            }
            if let DesiredBehavior::Exceptional {
                required_observation,
                ..
            } = &change.behavior
            {
                let matched = match required_observation {
                    ExceptionalObservation::Absent => {
                        matches!(observation.status(), ProbeStatus::Absent)
                    }
                    ExceptionalObservation::HumanRequired => matches!(
                        observation.status(),
                        ProbeStatus::Absent
                            | ProbeStatus::Broken { .. }
                            | ProbeStatus::Unknowable { .. }
                    ),
                    ExceptionalObservation::Healthy => {
                        matches!(
                            observation.status(),
                            ProbeStatus::Present { healthy: true, .. }
                                | ProbeStatus::TailscalePresent { healthy: true, .. }
                        )
                    }
                };
                if !matched {
                    return Err(PlanError::ExceptionalObservationMismatch);
                }
            }
        }

        let entries = desired
            .changes()
            .iter()
            .map(|change| {
                let observation = observed
                    .get(&change.subject)
                    .expect("all desired subjects were validated above");
                let action = match &change.behavior {
                    DesiredBehavior::Converge {
                        create,
                        repair,
                        done,
                    } => match observation.status() {
                        ProbeStatus::Absent => create.clone(),
                        ProbeStatus::Present { healthy: true, .. }
                        | ProbeStatus::TailscalePresent { healthy: true, .. } => done.clone(),
                        ProbeStatus::Present { healthy: false, .. }
                        | ProbeStatus::TailscalePresent { healthy: false, .. }
                        | ProbeStatus::Broken { .. } => repair.clone(),
                        ProbeStatus::Unknowable { .. } => {
                            unreachable!("unknowable observations were validated above")
                        }
                    },
                    DesiredBehavior::Exceptional { action, .. } => action.clone(),
                    DesiredBehavior::AdoptOrDefer { done, needs_human } => {
                        if matches!(
                            observation.status(),
                            ProbeStatus::Present { healthy: true, .. }
                                | ProbeStatus::TailscalePresent { healthy: true, .. }
                        ) {
                            done.clone()
                        } else {
                            needs_human.clone()
                        }
                    }
                };
                PlanEntry {
                    subject: change.subject.clone(),
                    component: change.component.clone(),
                    action: action.into_action(),
                }
            })
            .collect();
        Ok(Self { entries })
    }

    pub(crate) fn entries(&self) -> impl ExactSizeIterator<Item = &PlanEntry> {
        self.entries.iter()
    }

    /// Consumes the immutable plan while preserving the display grouping and
    /// the closed action value needed by the journaled apply path.
    pub(crate) fn into_component_actions(self) -> impl ExactSizeIterator<Item = (String, Action)> {
        self.entries
            .into_iter()
            .map(|entry| (entry.component.0, entry.action))
    }
}

pub(crate) struct PlanEntry {
    subject: ProbeId,
    component: ComponentName,
    action: Action,
}

impl PlanEntry {
    pub(crate) fn subject(&self) -> &ProbeId {
        &self.subject
    }

    pub(crate) fn operation(&self) -> PlanOperation {
        self.action.plan_operation()
    }

    pub(crate) fn component(&self) -> &str {
        self.component.as_str()
    }

    pub(crate) fn action(&self) -> &Action {
        &self.action
    }
}

/// Observes exactly once, computes the full plan, then renders it. No action
/// apply path, receipt API, filesystem mutation, or elevation route is in
/// scope for this function.
pub(crate) fn dry_run<W: Write>(
    catalog: &ProbeCatalog,
    desired: &DesiredState,
    writer: W,
) -> Result<SetupPlan, DryRunError> {
    let observed = catalog.observe();
    dry_run_observed(&observed, desired, writer)
}

pub(crate) fn dry_run_observed<W: Write>(
    observed: &ObservedState,
    desired: &DesiredState,
    writer: W,
) -> Result<SetupPlan, DryRunError> {
    let plan = SetupPlan::compute(observed, desired)?;
    render_dry_run(&plan, writer)?;
    Ok(plan)
}

/// Renders only after every action has been checked, so validation failures
/// cannot leave partial dry-run output in an otherwise valid writer.
pub(crate) fn render_dry_run<W: Write>(plan: &SetupPlan, mut writer: W) -> Result<(), DryRunError> {
    let rendered = format_plan(plan)?;
    writer
        .write_all(rendered.as_bytes())
        .map_err(DryRunError::Write)
}

fn format_plan(plan: &SetupPlan) -> Result<String, DryRunError> {
    let mut groups: Vec<(&ComponentName, Vec<(&PlanEntry, PlanOperation)>)> = Vec::new();
    for entry in &plan.entries {
        let check = entry.action.check().map_err(DryRunError::Action)?;
        let operation = display_operation(entry.operation(), &check);
        if let Some((_, entries)) = groups
            .iter_mut()
            .find(|(component, _)| *component == &entry.component)
        {
            entries.push((entry, operation));
        } else {
            groups.push((&entry.component, vec![(entry, operation)]));
        }
    }

    let mut output = String::new();
    for (component, entries) in groups {
        output.push_str(component.as_str());
        output.push_str(":\n");
        for (entry, operation) in entries {
            output.push_str("  ");
            output.push(operation_mark(operation));
            output.push(' ');
            output.push_str(entry.action.describe().as_str());
            match entry.action.privilege() {
                Privilege::None => {}
                Privilege::Root => output.push_str(" [sudo]"),
                Privilege::Admin => output.push_str(" [admin]"),
            }
            output.push('\n');
        }
    }
    Ok(output)
}

fn display_operation(desired: PlanOperation, check: &ActionCheck) -> PlanOperation {
    match check {
        ActionCheck::Done => PlanOperation::Done,
        ActionCheck::Todo => desired,
        ActionCheck::NeedsHuman(_) => PlanOperation::NeedsHuman,
    }
}

fn operation_mark(operation: PlanOperation) -> char {
    match operation {
        PlanOperation::Create => '+',
        PlanOperation::Reconfigure => '~',
        PlanOperation::Done => '✓',
        PlanOperation::NeedsHuman => '!',
        PlanOperation::Skipped => '.',
        PlanOperation::Remove => '-',
    }
}

impl fmt::Display for PlanOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Create => "create",
            Self::Reconfigure => "reconfigure",
            Self::Done => "done",
            Self::NeedsHuman => "needs human",
            Self::Skipped => "skipped",
            Self::Remove => "remove",
        })
    }
}

#[cfg(test)]
mod tests;

#[allow(unexpected_cfgs)]
mod fixture_support {
    #[cfg(plan_action_apply_fixture)]
    #[path = "hostile_apply.rs"]
    mod hostile_apply;
}

#[cfg(plan_receipt_forge_fixture)]
#[path = "hostile_receipt.rs"]
mod hostile_receipt;

#[cfg(any(
    plan_worker_native_authority_construct_fixture,
    plan_worker_native_mutation_call_fixture,
    plan_worker_prepare_fixture,
    plan_worker_execute_prepared_fixture,
    plan_worker_parameters_construct_fixture,
    plan_worker_verified_effect_construct_fixture
))]
#[path = "hostile_worker_directory_execution.rs"]
mod hostile_worker_directory_execution;
