//! Action-owned setup execution and receipt orchestration.

use super::{
    Action, ActionCheck, ActionEffect, ActionError, ActionName, JournalAuthority, PendingAction,
};
use crate::setup::receipt::{PendingReceiptOccurrence, ReceiptExecutionWitness, ReceiptStoreError};
use std::collections::HashSet;
use thiserror::Error;

pub(in crate::setup) struct CompletedExecutionToken {
    pending: Vec<PendingAction>,
    occurrences: Vec<PendingReceiptOccurrence>,
    receipt: ReceiptExecutionWitness,
}

impl CompletedExecutionToken {
    pub(in crate::setup) fn pending(&self) -> &[PendingAction] {
        &self.pending
    }

    pub(in crate::setup) fn occurrences(&self) -> &[PendingReceiptOccurrence] {
        &self.occurrences
    }

    pub(in crate::setup) fn receipt_witness(&self) -> &ReceiptExecutionWitness {
        &self.receipt
    }

    fn new(
        pending: Vec<PendingAction>,
        occurrences: Vec<PendingReceiptOccurrence>,
        receipt: ReceiptExecutionWitness,
    ) -> Result<Self, ReceiptStoreError> {
        if pending.len() != occurrences.len()
            || pending
                .iter()
                .zip(&occurrences)
                .any(|(action, occurrence)| !occurrence.matches_action(action.id()))
        {
            return Err(ReceiptStoreError::IntentConflict);
        }
        let mut action_ids = HashSet::with_capacity(pending.len());
        if pending
            .iter()
            .any(|action| !action_ids.insert(action.id().as_str()))
        {
            return Err(ReceiptStoreError::PrefixConflict);
        }
        Ok(Self {
            pending,
            occurrences,
            receipt,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(in crate::setup) struct ApplySummary {
    applied_count: usize,
    recovered_count: usize,
    noop_count: usize,
}

impl ApplySummary {
    pub(crate) fn applied_count(&self) -> usize {
        self.applied_count
    }

    pub(crate) fn recovered_count(&self) -> usize {
        self.recovered_count
    }

    pub(crate) fn noop_count(&self) -> usize {
        self.noop_count
    }

    pub(crate) fn is_nothing_to_do(&self, has_pending: bool) -> bool {
        self.applied_count == 0 && self.recovered_count == 0 && !has_pending
    }
}

pub(crate) struct ApplyReport {
    summary: ApplySummary,
    completion: CompletedExecutionToken,
}

impl std::fmt::Debug for ApplyReport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApplyReport")
            .field("summary", &self.summary)
            .field("pending_count", &self.completion.pending().len())
            .finish()
    }
}

impl ApplyReport {
    pub(crate) fn applied_count(&self) -> usize {
        self.summary.applied_count()
    }

    pub(crate) fn recovered_count(&self) -> usize {
        self.summary.recovered_count()
    }

    pub(crate) fn noop_count(&self) -> usize {
        self.summary.noop_count()
    }

    pub(crate) fn pending_count(&self) -> usize {
        self.completion.pending().len()
    }

    pub(crate) fn pending(&self) -> &[PendingAction] {
        self.completion.pending()
    }

    pub(in crate::setup) fn completion(&self) -> &CompletedExecutionToken {
        &self.completion
    }

    pub(crate) fn is_nothing_to_do(&self) -> bool {
        self.summary
            .is_nothing_to_do(!self.completion.pending().is_empty())
    }

    pub(crate) fn message(&self) -> &'static str {
        if self.is_nothing_to_do() {
            "nothing to do"
        } else if self.summary.applied_count == 0 && !self.completion.pending().is_empty() {
            "setup actions need human attention"
        } else if self.summary.applied_count == 0 && self.summary.recovered_count != 0 {
            "receipt recovered"
        } else {
            "setup actions applied"
        }
    }

    fn into_parts(self) -> (ApplySummary, CompletedExecutionToken) {
        (self.summary, self.completion)
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

pub(super) fn complete_authorized_execution(
    ordinary: ApplyReport,
    privileged_pending: Vec<PendingAction>,
    displayed_order: &[ActionName],
    store: &crate::setup::receipt::ReceiptStore,
    metadata: &mut crate::setup::receipt::ReceiptMetadataSource,
) -> Result<(ApplySummary, CompletedExecutionToken), ApplyPlanError> {
    let (summary, ordinary_completion) = ordinary.into_parts();
    let CompletedExecutionToken {
        pending: ordinary_pending,
        occurrences: ordinary_occurrences,
        receipt: ordinary_receipt,
    } = ordinary_completion;

    let mut displayed_positions = std::collections::HashMap::with_capacity(displayed_order.len());
    for (index, action) in displayed_order.iter().enumerate() {
        if displayed_positions.insert(action.as_str(), index).is_some() {
            return Err(ReceiptStoreError::PrefixConflict.into());
        }
    }
    let mut pending_ids = HashSet::with_capacity(ordinary_pending.len() + privileged_pending.len());
    for action in ordinary_pending.iter().chain(&privileged_pending) {
        if !pending_ids.insert(action.id().as_str()) {
            return Err(ReceiptStoreError::PrefixConflict.into());
        }
        if !displayed_positions.contains_key(action.id().as_str()) {
            return Err(ReceiptStoreError::IntentConflict.into());
        }
    }

    let authority = JournalAuthority(());
    let session = store.begin_apply(&authority)?;

    let current_receipt = session.complete_execution(&ordinary_occurrences, &authority)?;
    if current_receipt != ordinary_receipt {
        return Err(ReceiptStoreError::IntentConflict.into());
    }

    let mut pending_with_occurrences = ordinary_pending
        .into_iter()
        .zip(ordinary_occurrences)
        .collect::<Vec<_>>();
    for action in privileged_pending {
        let occurrence = session.record_pending(action.id(), metadata, &authority)?;
        pending_with_occurrences.push((action, occurrence));
    }

    pending_with_occurrences.sort_by_key(|(action, _)| displayed_positions[action.id().as_str()]);

    let (pending, occurrences): (Vec<_>, Vec<_>) = pending_with_occurrences.into_iter().unzip();
    let receipt = session.complete_execution(&occurrences, &authority)?;
    Ok((
        summary,
        CompletedExecutionToken::new(pending, occurrences, receipt)?,
    ))
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
    let mut summary = ApplySummary {
        applied_count: 0,
        recovered_count: 0,
        noop_count: 0,
    };
    let mut pending = Vec::new();
    let mut occurrences = Vec::new();
    for intent in session.pending_intents(&authority)? {
        match session.intent_phase(&intent, &authority) {
            crate::setup::receipt::ReceiptIntentPhase::Succeeded => {
                session.finalize_intent(&intent, &authority)?;
                summary.recovered_count += 1;
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
                        summary.applied_count += 1;
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
            ActionCheck::Done => summary.noop_count += 1,
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
                summary.applied_count += 1;
            }
            ActionCheck::NeedsHuman(needs_human) => {
                let occurrence = session.record_pending(action.name(), metadata, &authority)?;
                pending.push(PendingAction::new(action.name().clone(), needs_human));
                occurrences.push(occurrence);
            }
        }
    }
    let receipt = session.complete_execution(&occurrences, &authority)?;
    Ok(ApplyReport {
        summary,
        completion: CompletedExecutionToken::new(pending, occurrences, receipt)?,
    })
}
