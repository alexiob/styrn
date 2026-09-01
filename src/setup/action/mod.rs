//! Typed, idempotent setup action boundary.
//!
//! An [`Action`] is the sole normal mutation path for setup. Its public
//! `apply` method always checks first; the mutation hook is deliberately
//! confined to this module so callers cannot bypass that gate.

use std::fmt;
use thiserror::Error;

mod action_sealed {
    pub(crate) trait Sealed {}
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Privilege {
    None,
    Root,
    Admin,
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
    pub(in crate::setup::action) fn parse(value: &str) -> Result<Self, ActionError> {
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
    pub(in crate::setup::action) fn new(value: &str) -> Result<Self, ActionError> {
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

/// Validated text reserved for Phase 7 rendering; it is never executed here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScriptFragment(String);

impl ScriptFragment {
    pub(in crate::setup::action) fn new(value: &str) -> Result<Self, ActionError> {
        checked_text(value, ActionError::InvalidScriptFragment).map(Self)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
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

/// The canonical setup action contract.
///
/// Its mutation path is non-overridable: every ordinary caller reaches this
/// inherent [`Action::apply`] gate, which checks before dispatching to the
/// setup-owned implementation.
pub(crate) struct Action {
    implementation: Box<dyn ActionImpl>,
}

impl Action {
    pub(in crate::setup::action) fn from_impl(implementation: impl ActionImpl + 'static) -> Self {
        Self {
            implementation: Box::new(implementation),
        }
    }

    pub(crate) fn name(&self) -> &ActionName {
        self.implementation.name()
    }

    pub(crate) fn check(&self) -> Result<ActionCheck, ActionError> {
        self.implementation.check()
    }

    pub(crate) fn privilege(&self) -> Privilege {
        self.implementation.privilege()
    }

    pub(crate) fn describe(&self) -> &ActionDescription {
        self.implementation.describe()
    }

    pub(crate) fn apply(&mut self) -> Result<ApplyOutcome, ActionError> {
        match self.implementation.check()? {
            ActionCheck::Done => Ok(ApplyOutcome::Noop),
            ActionCheck::Todo => self
                .implementation
                .apply_mutation()
                .map(ApplyOutcome::Applied),
            ActionCheck::NeedsHuman(needs_human) => Ok(ApplyOutcome::NeedsHuman(needs_human)),
        }
    }

    pub(crate) fn revert(&mut self, effect: &ActionEffect) -> Result<(), ActionError> {
        self.implementation.revert(effect)
    }

    pub(crate) fn render_posix(&self) -> Result<ScriptFragment, ActionError> {
        self.implementation.render_posix()
    }

    pub(crate) fn render_powershell(&self) -> Result<ScriptFragment, ActionError> {
        self.implementation.render_powershell()
    }
}

/// Sealed implementation hooks for setup-owned action variants.
///
/// This trait intentionally has no public apply method. [`Action`] owns the
/// idempotency gate and is the sole normal setup mutation entry point.
pub(crate) trait ActionImpl: action_sealed::Sealed {
    fn name(&self) -> &ActionName;
    fn check(&self) -> Result<ActionCheck, ActionError>;
    fn privilege(&self) -> Privilege;
    fn describe(&self) -> &ActionDescription;
    fn apply_mutation(&mut self) -> Result<ActionEffect, ActionError>;

    fn revert(&mut self, _effect: &ActionEffect) -> Result<(), ActionError> {
        Err(ActionError::UnsupportedUntilPhase7 {
            action: self.name().clone(),
            operation: UnsupportedOperation::Revert,
        })
    }

    fn render_posix(&self) -> Result<ScriptFragment, ActionError> {
        Err(ActionError::UnsupportedUntilPhase7 {
            action: self.name().clone(),
            operation: UnsupportedOperation::RenderPosix,
        })
    }

    fn render_powershell(&self) -> Result<ScriptFragment, ActionError> {
        Err(ActionError::UnsupportedUntilPhase7 {
            action: self.name().clone(),
            operation: UnsupportedOperation::RenderPowerShell,
        })
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
