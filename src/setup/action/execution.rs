//! Action-owned setup execution and receipt orchestration.

use super::{Action, ActionCheck, ActionError, JournalAuthority};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ApplyReport {
    applied_count: usize,
    recovered_count: usize,
    noop_count: usize,
}

impl ApplyReport {
    pub(crate) fn applied_count(&self) -> usize {
        self.applied_count
    }

    pub(crate) fn recovered_count(&self) -> usize {
        self.recovered_count
    }

    pub(crate) fn is_nothing_to_do(&self) -> bool {
        self.applied_count == 0 && self.recovered_count == 0
    }

    pub(crate) fn message(&self) -> &'static str {
        if self.is_nothing_to_do() {
            "nothing to do"
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
    let mut action_names = std::collections::HashSet::with_capacity(plan.len());
    if plan
        .iter()
        .any(|action| !action_names.insert(action.name().as_str()))
    {
        return Err(crate::setup::receipt::ReceiptStoreError::IntentConflict.into());
    }
    let authority = JournalAuthority(());
    let session = store.begin_apply(&authority)?;
    let mut report = ApplyReport {
        applied_count: 0,
        recovered_count: 0,
        noop_count: 0,
    };
    for intent in session.pending_intents(&authority)? {
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
        match session.intent_phase(&intent, &authority) {
            crate::setup::receipt::ReceiptIntentPhase::Succeeded => {
                session.finalize_intent(&intent, &authority)?;
                report.recovered_count += 1;
            }
            crate::setup::receipt::ReceiptIntentPhase::Prepared => match action.check()? {
                ActionCheck::Todo => {
                    let finalized = action.execute_prepared()?;
                    if finalized != prepared {
                        return Err(crate::setup::receipt::ReceiptStoreError::IntentConflict.into());
                    }
                    let mut intent = intent;
                    session.mark_intent_succeeded(&mut intent, &authority)?;
                    session.finalize_intent(&intent, &authority)?;
                    report.applied_count += 1;
                }
                ActionCheck::Done | ActionCheck::NeedsHuman(_) => {
                    return Err(crate::setup::receipt::ReceiptStoreError::IntentConflict.into());
                }
            },
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
                let finalized = action.execute_prepared()?;
                if finalized != prepared {
                    return Err(crate::setup::receipt::ReceiptStoreError::IntentConflict.into());
                }
                session.mark_intent_succeeded(&mut intent, &authority)?;
                session.finalize_intent(&intent, &authority)?;
                report.applied_count += 1;
            }
            ActionCheck::NeedsHuman(_) => report.noop_count += 1,
        }
    }
    Ok(report)
}
