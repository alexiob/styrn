//! Action-owned setup execution and receipt orchestration.

use super::{Action, ActionCheck, ActionEffect, ActionError, JournalAuthority, NeedsHuman};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ApplyReport {
    applied_count: usize,
    recovered_count: usize,
    noop_count: usize,
    pending: Vec<NeedsHuman>,
}

impl ApplyReport {
    pub(crate) fn applied_count(&self) -> usize {
        self.applied_count
    }

    pub(crate) fn recovered_count(&self) -> usize {
        self.recovered_count
    }

    pub(crate) fn noop_count(&self) -> usize {
        self.noop_count
    }

    pub(crate) fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub(crate) fn pending(&self) -> &[NeedsHuman] {
        &self.pending
    }

    pub(crate) fn is_nothing_to_do(&self) -> bool {
        self.applied_count == 0 && self.recovered_count == 0 && self.pending.is_empty()
    }

    pub(crate) fn message(&self) -> &'static str {
        if self.is_nothing_to_do() {
            "nothing to do"
        } else if self.applied_count == 0 && !self.pending.is_empty() {
            "setup actions need human attention"
        } else if self.applied_count == 0 && self.recovered_count != 0 {
            "receipt recovered"
        } else {
            "setup actions applied"
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum ApplyPlanError {
    #[error(transparent)]
    Action(#[from] ActionError),
    #[error(transparent)]
    Receipt(#[from] crate::setup::receipt::ReceiptStoreError),
}

impl ApplyPlanError {
    pub(crate) fn error_code(&self) -> &'static str {
        match self {
            Self::Action(_) => "setup.apply_failed",
            Self::Receipt(error) => error.error_code(),
        }
    }

    pub(crate) fn exit_code(&self) -> u8 {
        13
    }
}

pub(super) fn apply_plan_with_journal(
    plan: &mut [Action],
    store: &crate::setup::receipt::ReceiptStore,
    metadata: &mut crate::setup::receipt::ReceiptMetadataSource,
) -> Result<ApplyReport, ApplyPlanError> {
    apply_plan_with_runner(plan, store, metadata, &mut DirectPreparedActionRunner)
}

pub(super) trait PreparedActionRunner {
    fn execute_prepared(
        &mut self,
        action: &mut Action,
        expected: &ActionEffect,
    ) -> Result<ActionEffect, ActionError>;
}

struct DirectPreparedActionRunner;

impl PreparedActionRunner for DirectPreparedActionRunner {
    fn execute_prepared(
        &mut self,
        action: &mut Action,
        _expected: &ActionEffect,
    ) -> Result<ActionEffect, ActionError> {
        action.execute_prepared()
    }
}

pub(super) fn apply_plan_with_runner<R: PreparedActionRunner>(
    plan: &mut [Action],
    store: &crate::setup::receipt::ReceiptStore,
    metadata: &mut crate::setup::receipt::ReceiptMetadataSource,
    runner: &mut R,
) -> Result<ApplyReport, ApplyPlanError> {
    let mut action_names = std::collections::HashSet::with_capacity(plan.len());
    if plan
        .iter()
        .any(|action| !action_names.insert(action.name().as_str()))
    {
        return Err(crate::setup::receipt::ReceiptStoreError::IntentConflict.into());
    }
    for action in plan.iter() {
        store.validate_action_privilege(action.privilege())?;
    }
    let authority = JournalAuthority(());
    let session = store.begin_apply(&authority)?;
    let mut report = ApplyReport {
        applied_count: 0,
        recovered_count: 0,
        noop_count: 0,
        pending: Vec::new(),
    };
    for intent in session.pending_intents(&authority)? {
        match session.intent_phase(&intent, &authority) {
            crate::setup::receipt::ReceiptIntentPhase::Succeeded => {
                session.finalize_intent(&intent, &authority)?;
                report.recovered_count += 1;
            }
            crate::setup::receipt::ReceiptIntentPhase::Prepared => {
                let action_id = session.intent_action_id(&intent, &authority);
                let action = plan
                    .iter_mut()
                    .find(|action| action.name().as_str() == action_id)
                    .ok_or(crate::setup::receipt::ReceiptStoreError::IntentConflict)?;
                let prepared = action.prepare_effect()?;
                if !session.intent_matches(
                    &intent,
                    action.name(),
                    action.privilege(),
                    &prepared,
                    &authority,
                )? {
                    return Err(crate::setup::receipt::ReceiptStoreError::IntentConflict.into());
                }
                match action.check()? {
                    ActionCheck::Todo => {
                        let finalized = runner.execute_prepared(action, &prepared)?;
                        if finalized != prepared {
                            return Err(
                                crate::setup::receipt::ReceiptStoreError::IntentConflict.into()
                            );
                        }
                        let mut intent = intent;
                        session.mark_intent_succeeded(&mut intent, &authority)?;
                        session.finalize_intent(&intent, &authority)?;
                        report.applied_count += 1;
                    }
                    ActionCheck::Done | ActionCheck::NeedsHuman(_) => {
                        return Err(crate::setup::receipt::ReceiptStoreError::IntentConflict.into());
                    }
                }
            }
        }
    }
    for action in plan {
        match action.check()? {
            ActionCheck::Done => report.noop_count += 1,
            ActionCheck::Todo => {
                let prepared = action.prepare_effect()?;
                let mut intent = session.prepare_intent(
                    action.name(),
                    action.privilege(),
                    &prepared,
                    metadata,
                    &authority,
                )?;
                session.interruption_after_prepare(&authority)?;
                let finalized = runner.execute_prepared(action, &prepared)?;
                if finalized != prepared {
                    return Err(crate::setup::receipt::ReceiptStoreError::IntentConflict.into());
                }
                session.mark_intent_succeeded(&mut intent, &authority)?;
                session.finalize_intent(&intent, &authority)?;
                report.applied_count += 1;
            }
            ActionCheck::NeedsHuman(needs_human) => report.pending.push(needs_human),
        }
    }
    Ok(report)
}
