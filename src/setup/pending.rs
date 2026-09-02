//! Shared pending-state publication and rendering boundary.
//!
//! Full `setup` CLI orchestration remains owned by T0.20.

use super::action::{PendingAction, PendingSeverity};
use crate::{manifest, output};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use std::{collections::HashSet, io::Write};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PendingPolicy {
    fail_on_pending: bool,
}

impl PendingPolicy {
    pub(crate) const fn new(fail_on_pending: bool) -> Self {
        Self { fail_on_pending }
    }

    pub(crate) fn evaluate(
        self,
        timestamp: DateTime<Utc>,
        pending: &[PendingAction],
    ) -> Result<PendingOutcome, PendingError> {
        let data = json!({"pending": pending_wire(pending)});
        let warnings = pending
            .iter()
            .map(|action| {
                output::Diagnostic::new(
                    output::ErrorCode::SetupNeedsHuman.as_str(),
                    action.needs_human().instructions().as_str(),
                    Some(json!({
                        "action_id": action.id().as_str(),
                        "severity": severity_name(action.severity()),
                    })),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        let (envelope, exit_code) = if self.fail_on_pending && !pending.is_empty() {
            (
                output::Envelope::failure(
                    "setup",
                    timestamp,
                    vec![output::ErrorDiagnostic::new(
                        output::ErrorCode::SetupNeedsHuman,
                        "setup has unresolved actions requiring human attention",
                        Some(json!({"pending": pending_wire(pending)})),
                    )?],
                    warnings,
                )?,
                output::StyrnExit::Setup,
            )
        } else {
            (
                output::Envelope::success("setup", timestamp, data, warnings)?,
                output::StyrnExit::Success,
            )
        };

        Ok(PendingOutcome {
            envelope,
            exit_code,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PendingOutcome {
    envelope: output::Envelope,
    exit_code: output::StyrnExit,
}

impl PendingOutcome {
    pub(crate) fn envelope(&self) -> &output::Envelope {
        &self.envelope
    }

    pub(crate) const fn exit_code(&self) -> output::StyrnExit {
        self.exit_code
    }
}

pub(super) struct PendingPublicationAuthority(());

/// Replaces only the manifest's current unresolved projection.
fn project_manifest(
    draft: &mut manifest::MachineManifestDraft,
    pending: &[PendingAction],
) -> Result<(), PendingError> {
    validate_unique_pending(pending)?;
    let mut projected = Vec::with_capacity(pending.len());
    for action in pending {
        projected.push(manifest::PendingAction {
            id: action.id().as_str().to_owned(),
            severity: manifest_severity(action.severity()),
            message: action.needs_human().instructions().as_str().to_owned(),
        });
    }
    draft.pending_actions = (!projected.is_empty()).then_some(projected);
    Ok(())
}

fn validate_unique_pending(pending: &[PendingAction]) -> Result<(), PendingError> {
    let mut ids = HashSet::with_capacity(pending.len());
    if pending
        .iter()
        .all(|action| ids.insert(action.id().as_str()))
    {
        Ok(())
    } else {
        Err(PendingError::DuplicateId)
    }
}

#[cfg(test)]
pub(super) fn project_manifest_for_test(
    draft: &mut manifest::MachineManifestDraft,
    pending: &[PendingAction],
) -> Result<(), PendingError> {
    project_manifest(draft, pending)
}

/// Publishes the complete current projection from either ordinary apply or the
/// authorization-aware execution report. T0.20 owns CLI invocation ordering.
pub(crate) fn publish_manifest(
    manifest_store: &manifest::MachineManifestStore,
    receipt_store: &super::receipt::ReceiptStore,
    draft: &mut manifest::MachineManifestDraft,
    pending: &[PendingAction],
    metadata: &mut super::receipt::ReceiptMetadataSource,
) -> Result<uuid::Uuid, PendingError> {
    validate_unique_pending(pending)?;
    let authority = PendingPublicationAuthority(());
    let session = receipt_store.begin_pending_publication(&authority)?;
    let prepared = session.prepare(pending, metadata, &authority)?;
    let mut candidate = draft.clone();
    project_manifest(&mut candidate, pending)?;
    let machine_id = manifest_store.write_generated(&candidate)?;
    session.commit(prepared, &authority)?;
    *draft = candidate;
    Ok(machine_id)
}

pub(crate) fn render_human(
    mut writer: impl Write,
    pending: &[PendingAction],
) -> Result<(), PendingError> {
    if pending.is_empty() {
        return Ok(());
    }
    writeln!(writer, "Pending actions requiring your attention:")?;
    for action in pending {
        writeln!(
            writer,
            "- [{}] {}: {}",
            severity_name(action.severity()),
            action.id().as_str(),
            action.needs_human().instructions().as_str()
        )?;
        if let Some(fragment_id) = action.fragment_action_id() {
            writeln!(
                writer,
                "  deferred action: {fragment_id}; not rendered or executed"
            )?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct PendingWire<'a> {
    id: &'a str,
    severity: &'static str,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    deferred_action: Option<&'a str>,
}

fn pending_wire(pending: &[PendingAction]) -> Vec<PendingWire<'_>> {
    pending
        .iter()
        .map(|action| PendingWire {
            id: action.id().as_str(),
            severity: severity_name(action.severity()),
            message: action.needs_human().instructions().as_str(),
            deferred_action: action.fragment_action_id(),
        })
        .collect()
}

const fn severity_name(severity: PendingSeverity) -> &'static str {
    match severity {
        PendingSeverity::Info => "info",
        PendingSeverity::Warning => "warning",
        PendingSeverity::Error => "error",
    }
}

const fn manifest_severity(severity: PendingSeverity) -> manifest::PendingSeverity {
    match severity {
        PendingSeverity::Info => manifest::PendingSeverity::Info,
        PendingSeverity::Warning => manifest::PendingSeverity::Warning,
        PendingSeverity::Error => manifest::PendingSeverity::Error,
    }
}

#[derive(Debug, Error)]
pub(crate) enum PendingError {
    #[error("pending action identifiers must be unique")]
    DuplicateId,
    #[error(transparent)]
    Output(#[from] output::OutputError),
    #[error(transparent)]
    Manifest(#[from] manifest::ManifestError),
    #[error(transparent)]
    Receipt(#[from] super::receipt::ReceiptStoreError),
    #[error("could not render pending actions")]
    Render(#[from] std::io::Error),
}

impl PendingError {
    pub(crate) fn error_code(&self) -> &'static str {
        match self {
            Self::DuplicateId => output::ErrorCode::SetupPlanInvalid.as_str(),
            Self::Receipt(error) => error.error_code(),
            Self::Output(_) | Self::Manifest(_) | Self::Render(_) => {
                output::ErrorCode::SetupApplyFailed.as_str()
            }
        }
    }

    pub(crate) const fn exit_code(&self) -> output::StyrnExit {
        output::StyrnExit::Setup
    }
}
