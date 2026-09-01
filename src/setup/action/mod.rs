//! Typed, idempotent setup action boundary.
//!
//! An [`Action`] is the sole normal mutation path for setup. Its public
//! `apply` method always checks first; the mutation hook is deliberately
//! confined to this module so callers cannot bypass that gate.

use std::fmt;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ActionCheck {
    Done,
    Todo,
    NeedsHuman(NeedsHuman),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ApplyOutcome {
    Noop,
    Applied(ActionEffect),
    NeedsHuman(NeedsHuman),
}

/// An intentionally narrow, in-memory placeholder until T0.11 owns receipts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActionEffect {
    Changed,
}

#[cfg(test)]
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

#[cfg(test)]
#[derive(Clone)]
pub(super) struct TestMetrics {
    check_calls: Arc<AtomicUsize>,
    mutation_calls: Arc<AtomicUsize>,
}

#[cfg(test)]
impl TestMetrics {
    pub(super) fn check_calls(&self) -> usize {
        self.check_calls.load(Ordering::SeqCst)
    }

    pub(super) fn mutation_calls(&self) -> usize {
        self.mutation_calls.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Privilege {
    None,
    Root,
    Admin,
}

/// The closed set of semantic plan marks from design Part 15.4.4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PlanOperation {
    Create,
    Reconfigure,
    Done,
    NeedsHuman,
    Skipped,
    Remove,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NeedsHuman {
    instructions: HumanInstructions,
    fragment: Option<ScriptFragment>,
}

impl NeedsHuman {
    pub(in crate::setup::action) fn new(
        instructions: HumanInstructions,
        fragment: Option<ScriptFragment>,
    ) -> Self {
        Self {
            instructions,
            fragment,
        }
    }

    pub(crate) fn instructions(&self) -> &HumanInstructions {
        &self.instructions
    }

    pub(crate) fn fragment(&self) -> Option<&ScriptFragment> {
        self.fragment.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ActionName(String);

impl ActionName {
    pub(in crate::setup) fn parse(value: &str) -> Result<Self, ActionError> {
        if valid_action_name(value) && super::validate_probe_static_text(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(ActionError::InvalidActionName)
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ActionName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ActionDescription(String);

impl ActionDescription {
    pub(in crate::setup) fn new(value: &str) -> Result<Self, ActionError> {
        checked_text(value, ActionError::InvalidDescription).map(Self)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HumanInstructions(String);

impl HumanInstructions {
    pub(in crate::setup::action) fn new(value: &str) -> Result<Self, ActionError> {
        checked_text(value, ActionError::InvalidInstructions).map(Self)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// A closed, non-executable placeholder for Phase 7 script rendering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ScriptFragment {
    DeferredAction(ActionName),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnsupportedOperation {
    Revert,
    RenderPosix,
    RenderPowerShell,
}

impl fmt::Display for UnsupportedOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Revert => "revert",
            Self::RenderPosix => "POSIX rendering",
            Self::RenderPowerShell => "PowerShell rendering",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub(crate) enum ActionError {
    #[error("action name is invalid")]
    InvalidActionName,
    #[error("action description is invalid")]
    InvalidDescription,
    #[error("human action instructions are invalid")]
    InvalidInstructions,
    #[error("script fragment is invalid")]
    InvalidScriptFragment,
    #[error("action `{action}` check failed")]
    CheckFailed { action: ActionName },
    #[error("action `{action}` apply failed")]
    ApplyFailed { action: ActionName },
    #[error("action `{action}` does not support {operation} until Phase 7")]
    UnsupportedUntilPhase7 {
        action: ActionName,
        operation: UnsupportedOperation,
    },
}

impl ActionError {
    pub(in crate::setup::action) fn check_failed(action: ActionName) -> Self {
        Self::CheckFailed { action }
    }

    pub(in crate::setup::action) fn apply_failed(action: ActionName) -> Self {
        Self::ApplyFailed { action }
    }
}

/// The closed setup action plan type. Future component actions extend this
/// enum; there is no open implementation trait or raw mutation entry point.
pub(crate) enum Action {
    Foundation(FoundationAction),
    #[cfg(test)]
    Test(TestAction),
}

pub(crate) type ActionPlan = Vec<Action>;

pub(crate) struct FoundationAction {
    name: ActionName,
    description: ActionDescription,
    privilege: Privilege,
    operation: PlanOperation,
    check: ActionCheck,
}

#[cfg(test)]
pub(crate) struct TestAction {
    name: ActionName,
    description: ActionDescription,
    privilege: Privilege,
    state: Arc<Mutex<Vec<u8>>>,
    metrics: TestMetrics,
    behavior: TestBehavior,
}

#[cfg(test)]
#[derive(Clone)]
enum TestBehavior {
    StateDriven,
    NeedsHuman(NeedsHuman),
    CheckFailure,
    ApplyFailure,
}

mod gate {
    use super::*;

    impl Action {
        /// Builds a plan-only foundation action from already validated data.
        /// Component actions added by later phases remain enum variants.
        pub(in crate::setup) fn planned(
            name: ActionName,
            description: ActionDescription,
            privilege: Privilege,
            operation: PlanOperation,
        ) -> Self {
            let check = match operation {
                PlanOperation::Create | PlanOperation::Reconfigure | PlanOperation::Remove => {
                    ActionCheck::Todo
                }
                PlanOperation::Done | PlanOperation::Skipped => ActionCheck::Done,
                PlanOperation::NeedsHuman => ActionCheck::NeedsHuman(NeedsHuman {
                    instructions: HumanInstructions(description.as_str().to_owned()),
                    fragment: None,
                }),
            };
            Self::Foundation(FoundationAction {
                name,
                description,
                privilege,
                operation,
                check,
            })
        }

        #[cfg(test)]
        pub(super) fn test_state_driven(
            privilege: Privilege,
            state: Arc<Mutex<Vec<u8>>>,
        ) -> (Self, TestMetrics) {
            Self::test_action(privilege, state, TestBehavior::StateDriven)
        }

        #[cfg(test)]
        pub(super) fn test_needs_human(
            privilege: Privilege,
            state: Arc<Mutex<Vec<u8>>>,
            needs_human: NeedsHuman,
        ) -> (Self, TestMetrics) {
            Self::test_action(privilege, state, TestBehavior::NeedsHuman(needs_human))
        }

        #[cfg(test)]
        pub(super) fn test_check_failure(
            privilege: Privilege,
            state: Arc<Mutex<Vec<u8>>>,
        ) -> (Self, TestMetrics) {
            Self::test_action(privilege, state, TestBehavior::CheckFailure)
        }

        #[cfg(test)]
        pub(super) fn test_apply_failure(
            privilege: Privilege,
            state: Arc<Mutex<Vec<u8>>>,
        ) -> (Self, TestMetrics) {
            Self::test_action(privilege, state, TestBehavior::ApplyFailure)
        }

        #[cfg(test)]
        fn test_action(
            privilege: Privilege,
            state: Arc<Mutex<Vec<u8>>>,
            behavior: TestBehavior,
        ) -> (Self, TestMetrics) {
            let metrics = TestMetrics {
                check_calls: Arc::new(AtomicUsize::new(0)),
                mutation_calls: Arc::new(AtomicUsize::new(0)),
            };
            let action = TestAction {
                name: ActionName::parse("test.state").expect("test action name must be valid"),
                description: ActionDescription::new("Converge test state")
                    .expect("test description must be valid"),
                privilege,
                state,
                metrics: metrics.clone(),
                behavior,
            };
            (Self::Test(action), metrics)
        }

        pub(crate) fn name(&self) -> &ActionName {
            match self {
                Self::Foundation(action) => &action.name,
                #[cfg(test)]
                Self::Test(action) => &action.name,
            }
        }

        pub(crate) fn check(&self) -> Result<ActionCheck, ActionError> {
            match self {
                Self::Foundation(action) => Ok(action.check.clone()),
                #[cfg(test)]
                Self::Test(action) => {
                    action.metrics.check_calls.fetch_add(1, Ordering::SeqCst);
                    match &action.behavior {
                        TestBehavior::StateDriven | TestBehavior::ApplyFailure => {
                            if action.state.lock().unwrap().as_slice() == [1] {
                                Ok(ActionCheck::Done)
                            } else {
                                Ok(ActionCheck::Todo)
                            }
                        }
                        TestBehavior::NeedsHuman(needs_human) => {
                            Ok(ActionCheck::NeedsHuman(needs_human.clone()))
                        }
                        TestBehavior::CheckFailure => {
                            Err(ActionError::check_failed(action.name.clone()))
                        }
                    }
                }
            }
        }

        pub(crate) fn privilege(&self) -> Privilege {
            match self {
                Self::Foundation(action) => action.privilege,
                #[cfg(test)]
                Self::Test(action) => action.privilege,
            }
        }

        pub(crate) fn plan_operation(&self) -> PlanOperation {
            match self {
                Self::Foundation(action) => action.operation,
                #[cfg(test)]
                Self::Test(_) => PlanOperation::Reconfigure,
            }
        }

        pub(crate) fn describe(&self) -> &ActionDescription {
            match self {
                Self::Foundation(action) => &action.description,
                #[cfg(test)]
                Self::Test(action) => &action.description,
            }
        }

        pub(in crate::setup::action) fn apply(&mut self) -> Result<ApplyOutcome, ActionError> {
            match self.check()? {
                ActionCheck::Done => Ok(ApplyOutcome::Noop),
                ActionCheck::Todo => execute(self).map(ApplyOutcome::Applied),
                ActionCheck::NeedsHuman(needs_human) => Ok(ApplyOutcome::NeedsHuman(needs_human)),
            }
        }

        pub(crate) fn revert(&mut self, _effect: &ActionEffect) -> Result<(), ActionError> {
            Err(ActionError::UnsupportedUntilPhase7 {
                action: self.name().clone(),
                operation: UnsupportedOperation::Revert,
            })
        }

        pub(crate) fn render_posix(&self) -> Result<ScriptFragment, ActionError> {
            Err(ActionError::UnsupportedUntilPhase7 {
                action: self.name().clone(),
                operation: UnsupportedOperation::RenderPosix,
            })
        }

        pub(crate) fn render_powershell(&self) -> Result<ScriptFragment, ActionError> {
            Err(ActionError::UnsupportedUntilPhase7 {
                action: self.name().clone(),
                operation: UnsupportedOperation::RenderPowerShell,
            })
        }
    }

    fn execute(action: &mut Action) -> Result<ActionEffect, ActionError> {
        match action {
            Action::Foundation(action) => Err(ActionError::apply_failed(action.name.clone())),
            #[cfg(test)]
            Action::Test(action) => {
                action.metrics.mutation_calls.fetch_add(1, Ordering::SeqCst);
                if matches!(action.behavior, TestBehavior::ApplyFailure) {
                    return Err(ActionError::apply_failed(action.name.clone()));
                }
                *action.state.lock().unwrap() = vec![1];
                Ok(ActionEffect::Changed)
            }
        }
    }
}

fn checked_text(value: &str, error: ActionError) -> Result<String, ActionError> {
    if super::validate_probe_static_text(value) {
        Ok(value.to_owned())
    } else {
        Err(error)
    }
}

fn valid_action_name(value: &str) -> bool {
    value.split('.').count() >= 2 && value.split('.').all(valid_action_name_segment)
}

fn valid_action_name_segment(segment: &str) -> bool {
    let mut characters = segment.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && !segment.ends_with('-')
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

#[cfg(test)]
mod tests;

#[allow(unexpected_cfgs)]
mod fixture_support {
    #[cfg(action_owned_descendant_fixture)]
    #[path = "owned_descendant_impl.rs"]
    mod owned_descendant;
}
