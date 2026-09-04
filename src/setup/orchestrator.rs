use super::{
    action::{
        self, Action, ActionCheck, ActionDescription, ActionExecutionResult, ActionName,
        ActionPlan, PendingSeverity, PlanOperation, Privilege,
    },
    pending::{self, PendingPolicy},
    plan::SetupPlan,
    probe::{
        self, production_rootless_catalog, production_rootless_ssh_readiness,
        rootless_baseline_desired_state, ProbeStatus,
    },
    receipt::{configured_receipt_store, ReceiptMetadataSource, ReceiptStore},
    EffectiveRootlessSetup, ObservedState,
};
use crate::{manifest, platform};
use std::{collections::BTreeMap, fmt, path::Path};

const CURRENT_USER_CAVEAT: &str = "Current-user mode provides no OS-account isolation, no controller-credential isolation, and no same-user Styrn-state integrity boundary.";
const ENROLLMENT_INTEGRITY_GUIDANCE: &str = "Read this fingerprint from the worker's own console or another session you initiated; do not relay it through a channel you would not trust for host-key pinning.";
const CONTROLLER_RECOVERY_GUIDANCE: &str = "If the controller has no identity, run `styrn controller init`; authorize its printed public key on this worker with `styrn setup --authorized-keys <public-key>`, then rerun setup.";
const CONCURRENT_PUBLICATION_RETRIES: usize = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EnrollmentCard {
    name: String,
    host: String,
    user: String,
    fingerprint: String,
    command: String,
}

impl EnrollmentCard {
    pub(crate) fn new(
        name: &str,
        host: &str,
        user: &str,
        port: u16,
        host_key: &crate::transport::PinnedHostKey,
    ) -> Result<Self, RootlessSetupError> {
        if name.is_empty()
            || name.len() > 255
            || !super::validate_probe_static_text(name)
            || port != 22
            || crate::transport::validate_ssh_destination(host, user, port).is_err()
        {
            return Err(RootlessSetupError::PlanInvalid);
        }
        let fingerprint = host_key.fingerprint().to_owned();
        crate::transport::validate_host_key_fingerprint(&fingerprint)
            .map_err(|_| RootlessSetupError::PlanInvalid)?;
        Ok(Self {
            name: name.to_owned(),
            host: host.to_owned(),
            user: user.to_owned(),
            command: format!("styrn host enroll {host} --user {user} --fingerprint {fingerprint}"),
            fingerprint,
        })
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn user(&self) -> &str {
        &self.user
    }

    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub(crate) fn command(&self) -> &str {
        &self.command
    }

    pub(crate) const fn integrity_guidance(&self) -> &'static str {
        ENROLLMENT_INTEGRITY_GUIDANCE
    }

    pub(crate) const fn controller_recovery(&self) -> &'static str {
        CONTROLLER_RECOVERY_GUIDANCE
    }
}

pub(crate) struct RootlessSetupPlan {
    effective: EffectiveRootlessSetup,
    plan_items: Vec<RootlessSetupPlanItem>,
    actions: ActionPlan,
    draft: manifest::MachineManifestDraft,
    receipt_store: ReceiptStore,
    manifest_store: manifest::MachineManifestStore,
    candidate_host_key: CandidateHostKey,
}

impl fmt::Debug for RootlessSetupPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootlessSetupPlan")
            .field("plan_item_count", &self.plan_items.len())
            .field("action_count", &self.actions.len())
            .field("receipt", &self.receipt_store.path())
            .field("manifest", &self.manifest_store.path())
            .finish()
    }
}

impl RootlessSetupPlan {
    pub(crate) fn effective(&self) -> &EffectiveRootlessSetup {
        &self.effective
    }

    pub(crate) fn plan_items(&self) -> &[RootlessSetupPlanItem] {
        &self.plan_items
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RootlessSetupPlanItem {
    action_id: String,
    component: String,
    operation: &'static str,
    privilege: &'static str,
    description: String,
    scope: &'static str,
    role: &'static str,
    account: &'static str,
    security_caveat: &'static str,
}

impl RootlessSetupPlanItem {
    pub(crate) fn action_id(&self) -> &str {
        &self.action_id
    }

    pub(crate) fn component(&self) -> &str {
        &self.component
    }

    pub(crate) const fn operation(&self) -> &'static str {
        self.operation
    }

    pub(crate) const fn privilege(&self) -> &'static str {
        self.privilege
    }

    pub(crate) fn description(&self) -> &str {
        &self.description
    }

    pub(crate) const fn scope(&self) -> &'static str {
        self.scope
    }

    pub(crate) const fn role(&self) -> &'static str {
        self.role
    }

    pub(crate) const fn account(&self) -> &'static str {
        self.account
    }

    pub(crate) const fn security_caveat(&self) -> &'static str {
        self.security_caveat
    }
}

pub(crate) struct RootlessSetupOutcome {
    plan_items: Vec<RootlessSetupPlanItem>,
    results: Vec<ActionExecutionResult>,
    pending: Vec<RootlessPendingResult>,
    manifest_path: std::path::PathBuf,
    receipt_path: std::path::PathBuf,
    security_caveat: &'static str,
    machine_id: uuid::Uuid,
    enrollment_card: Option<EnrollmentCard>,
}

impl fmt::Debug for RootlessSetupOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootlessSetupOutcome")
            .field("plan_item_count", &self.plan_items.len())
            .field("results", &self.results)
            .field("pending_count", &self.pending.len())
            .field("manifest", &self.manifest_path)
            .field("receipt", &self.receipt_path)
            .field("machine_id", &self.machine_id)
            .field("enrollment_card", &self.enrollment_card)
            .finish()
    }
}

impl RootlessSetupOutcome {
    pub(crate) fn plan_items(&self) -> &[RootlessSetupPlanItem] {
        &self.plan_items
    }

    pub(in crate::setup) fn results(&self) -> &[ActionExecutionResult] {
        &self.results
    }

    pub(crate) fn execution_results(&self) -> impl Iterator<Item = (&str, &str)> {
        self.results
            .iter()
            .map(|result| (result.action_id(), result.status().as_str()))
    }

    pub(crate) fn pending(&self) -> &[RootlessPendingResult] {
        &self.pending
    }

    pub(crate) fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    pub(crate) fn receipt_path(&self) -> &Path {
        &self.receipt_path
    }

    pub(crate) const fn security_caveat(&self) -> &'static str {
        self.security_caveat
    }

    pub(in crate::setup) const fn machine_id(&self) -> uuid::Uuid {
        self.machine_id
    }

    pub(crate) const fn enrollment_card(&self) -> Option<&EnrollmentCard> {
        self.enrollment_card.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RootlessPendingResult {
    action_id: String,
    severity: &'static str,
    message: String,
}

impl RootlessPendingResult {
    pub(crate) fn action_id(&self) -> &str {
        &self.action_id
    }

    pub(crate) const fn severity(&self) -> &'static str {
        self.severity
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

pub(crate) enum RootlessSetupError {
    ProbeFailed,
    PlanInvalid,
    ApplyFailed,
    ReceiptConflict,
    OperationFailed {
        error_code: &'static str,
        context: RootlessFailureContext,
    },
    NeedsHuman(Box<RootlessSetupOutcome>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RootlessFailureContext {
    phase: &'static str,
    action_id: String,
    cause_category: &'static str,
    remediation: &'static str,
}

impl fmt::Debug for RootlessSetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ProbeFailed => "RootlessSetupError::ProbeFailed",
            Self::PlanInvalid => "RootlessSetupError::PlanInvalid",
            Self::ApplyFailed => "RootlessSetupError::ApplyFailed",
            Self::ReceiptConflict => "RootlessSetupError::ReceiptConflict",
            Self::OperationFailed { .. } => "RootlessSetupError::OperationFailed",
            Self::NeedsHuman(_) => "RootlessSetupError::NeedsHuman",
        })
    }
}

impl fmt::Display for RootlessSetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ProbeFailed => "rootless setup preflight could not capture the current host",
            Self::PlanInvalid => "rootless setup plan is invalid",
            Self::ApplyFailed => "rootless setup apply failed",
            Self::ReceiptConflict => "rootless setup receipt conflicts with the requested plan",
            Self::OperationFailed { context, .. } => {
                return write!(
                    formatter,
                    "rootless setup {} operation `{}` failed ({}); {}",
                    context.phase, context.action_id, context.cause_category, context.remediation
                );
            }
            Self::NeedsHuman(_) => {
                "rootless setup has unresolved actions requiring human attention"
            }
        })
    }
}

impl std::error::Error for RootlessSetupError {}

impl RootlessSetupError {
    pub(crate) const fn error_code(&self) -> &'static str {
        match self {
            Self::ProbeFailed => "setup.probe_failed",
            Self::PlanInvalid => "setup.plan_invalid",
            Self::ApplyFailed => "setup.apply_failed",
            Self::ReceiptConflict => "setup.receipt_conflict",
            Self::OperationFailed { error_code, .. } => error_code,
            Self::NeedsHuman(_) => "setup.needs_human",
        }
    }

    pub(in crate::setup) const fn exit_code(&self) -> u8 {
        13
    }

    pub(crate) const fn outcome(&self) -> Option<&RootlessSetupOutcome> {
        match self {
            Self::NeedsHuman(outcome) => Some(outcome),
            _ => None,
        }
    }

    pub(crate) fn details(&self) -> Option<serde_json::Value> {
        let Self::OperationFailed { context, .. } = self else {
            return None;
        };
        Some(serde_json::json!({
            "phase": context.phase,
            "action_id": context.action_id,
            "cause_category": context.cause_category,
            "remediation": context.remediation,
        }))
    }

    #[cfg(test)]
    pub(crate) fn operation_failed_for_output_test() -> Self {
        Self::OperationFailed {
            error_code: "setup.apply_failed",
            context: RootlessFailureContext {
                phase: "execution",
                action_id: "identity.directory.root".to_owned(),
                cause_category: "action_apply",
                remediation: "correct the reported setup operation posture and retry setup",
            },
        }
    }
}

pub(crate) fn prepare_rootless_setup(
    effective: EffectiveRootlessSetup,
) -> Result<RootlessSetupPlan, RootlessSetupError> {
    let context =
        platform::SetupExecutionContext::capture().map_err(|_| RootlessSetupError::ProbeFailed)?;
    let directory_actions = action::current_user_worker_directory_plan(&context)
        .map_err(|_| RootlessSetupError::ProbeFailed)?;
    let principal = context.original_principal().clone();
    let receipt_store = configured_receipt_store().map_err(map_receipt_preflight_error)?;
    let manifest_store =
        manifest::configured_manifest_store().map_err(|_| RootlessSetupError::ProbeFailed)?;
    prepare_resolved_rootless_setup(
        effective,
        principal,
        directory_actions,
        receipt_store,
        manifest_store,
        RootlessSetupCandidates {
            layout: CandidateLayout::Canonical,
            ssh_directory: CandidateSshDirectory::Canonical,
            host_key: CandidateHostKey::Discover,
        },
    )
}

#[cfg(test)]
pub(in crate::setup) fn prepare_rootless_setup_for_test(
    effective: EffectiveRootlessSetup,
    context: platform::SetupExecutionContext,
    layout: platform::WorkerDirectoryLayout,
    receipt_store: ReceiptStore,
    manifest_store: manifest::MachineManifestStore,
) -> Result<RootlessSetupPlan, RootlessSetupError> {
    if context.original_principal() != layout.worker_principal() {
        return Err(RootlessSetupError::ProbeFailed);
    }
    let creation_anchor = layout
        .materialization_nodes()
        .into_iter()
        .find_map(|node| match node {
            platform::WorkerDirectoryNode::Support { .. } => layout
                .path_for_node(node)
                .and_then(|path| path.parent().map(Path::to_path_buf)),
            _ => None,
        });
    let (directory_actions, derived_layout) =
        action::current_user_worker_directory_plan_for_orchestrator_test(
            &context,
            layout.root().to_path_buf(),
            creation_anchor,
        )
        .map_err(|_| RootlessSetupError::ProbeFailed)?;
    if derived_layout != layout {
        return Err(RootlessSetupError::ProbeFailed);
    }
    let principal = context.original_principal().clone();
    prepare_resolved_rootless_setup(
        effective,
        principal,
        directory_actions,
        receipt_store,
        manifest_store,
        RootlessSetupCandidates {
            layout: CandidateLayout::Exact(Box::new(layout)),
            ssh_directory: CandidateSshDirectory::Unavailable,
            host_key: CandidateHostKey::Unavailable,
        },
    )
}

#[cfg(test)]
pub(in crate::setup) fn prepare_rootless_setup_for_test_with_ssh_directory(
    effective: EffectiveRootlessSetup,
    context: platform::SetupExecutionContext,
    layout: platform::WorkerDirectoryLayout,
    receipt_store: ReceiptStore,
    manifest_store: manifest::MachineManifestStore,
    ssh_directory: std::path::PathBuf,
) -> Result<RootlessSetupPlan, RootlessSetupError> {
    if context.original_principal() != layout.worker_principal() {
        return Err(RootlessSetupError::ProbeFailed);
    }
    let (directory_actions, derived_layout) =
        action::current_user_worker_directory_plan_for_orchestrator_test(
            &context,
            layout.root().to_path_buf(),
            layout
                .materialization_nodes()
                .into_iter()
                .find_map(|node| match node {
                    platform::WorkerDirectoryNode::Support { .. } => layout
                        .path_for_node(node)
                        .and_then(|path| path.parent().map(Path::to_path_buf)),
                    _ => None,
                }),
        )
        .map_err(|_| RootlessSetupError::ProbeFailed)?;
    if derived_layout != layout {
        return Err(RootlessSetupError::ProbeFailed);
    }
    let principal = context.original_principal().clone();
    prepare_resolved_rootless_setup(
        effective,
        principal,
        directory_actions,
        receipt_store,
        manifest_store,
        RootlessSetupCandidates {
            layout: CandidateLayout::Exact(Box::new(layout)),
            ssh_directory: CandidateSshDirectory::Exact(ssh_directory),
            host_key: CandidateHostKey::Unavailable,
        },
    )
}

#[cfg(test)]
pub(in crate::setup) fn prepare_rootless_setup_for_test_with_ssh_directory_and_host_key(
    effective: EffectiveRootlessSetup,
    context: platform::SetupExecutionContext,
    layout: platform::WorkerDirectoryLayout,
    receipt_store: ReceiptStore,
    manifest_store: manifest::MachineManifestStore,
    ssh_directory: std::path::PathBuf,
    host_key: crate::transport::PinnedHostKey,
) -> Result<RootlessSetupPlan, RootlessSetupError> {
    if context.original_principal() != layout.worker_principal() {
        return Err(RootlessSetupError::ProbeFailed);
    }
    let (directory_actions, derived_layout) =
        action::current_user_worker_directory_plan_for_orchestrator_test(
            &context,
            layout.root().to_path_buf(),
            layout
                .materialization_nodes()
                .into_iter()
                .find_map(|node| match node {
                    platform::WorkerDirectoryNode::Support { .. } => layout
                        .path_for_node(node)
                        .and_then(|path| path.parent().map(Path::to_path_buf)),
                    _ => None,
                }),
        )
        .map_err(|_| RootlessSetupError::ProbeFailed)?;
    if derived_layout != layout {
        return Err(RootlessSetupError::ProbeFailed);
    }
    let principal = context.original_principal().clone();
    prepare_resolved_rootless_setup(
        effective,
        principal,
        directory_actions,
        receipt_store,
        manifest_store,
        RootlessSetupCandidates {
            layout: CandidateLayout::Exact(Box::new(layout)),
            ssh_directory: CandidateSshDirectory::Exact(ssh_directory),
            host_key: CandidateHostKey::Exact(host_key),
        },
    )
}

struct RootlessSetupCandidates {
    layout: CandidateLayout,
    ssh_directory: CandidateSshDirectory,
    host_key: CandidateHostKey,
}

enum CandidateLayout {
    Canonical,
    #[cfg(test)]
    Exact(Box<platform::WorkerDirectoryLayout>),
}

enum CandidateSshDirectory {
    Canonical,
    #[cfg(test)]
    Exact(std::path::PathBuf),
    #[cfg(test)]
    Unavailable,
}

#[derive(Clone)]
enum CandidateHostKey {
    Discover,
    #[cfg(test)]
    Exact(crate::transport::PinnedHostKey),
    #[cfg(test)]
    Unavailable,
}

impl CandidateHostKey {
    fn discover(
        &self,
        host: &str,
        port: u16,
        expected_fingerprint: Option<&str>,
    ) -> Option<crate::transport::PinnedHostKey> {
        match self {
            Self::Discover => {
                let scanner = platform::verified_native_ssh_keyscan_path().ok()?;
                crate::transport::SshTransport::new(
                    std::path::PathBuf::from("unused"),
                    scanner,
                    std::path::PathBuf::from("unused"),
                )
                .scan_host_key_for_setup(host, port, expected_fingerprint)
                .ok()
            }
            #[cfg(test)]
            Self::Exact(host_key)
                if expected_fingerprint
                    .is_none_or(|expected| expected == host_key.fingerprint()) =>
            {
                Some(host_key.clone())
            }
            #[cfg(test)]
            Self::Exact(_) => None,
            #[cfg(test)]
            Self::Unavailable => None,
        }
    }
}

fn prepare_resolved_rootless_setup(
    effective: EffectiveRootlessSetup,
    principal: platform::WorkerPrincipal,
    mut actions: ActionPlan,
    receipt_store: ReceiptStore,
    manifest_store: manifest::MachineManifestStore,
    candidates: RootlessSetupCandidates,
) -> Result<RootlessSetupPlan, RootlessSetupError> {
    let RootlessSetupCandidates {
        layout: candidate_layout,
        ssh_directory: candidate_ssh_directory,
        host_key: candidate_host_key,
    } = candidates;
    if receipt_store.installation_scope() != platform::InstallationScope::User
        || receipt_store.worker_principal() != &principal
        || manifest_store.installation_scope() != platform::InstallationScope::User
        || manifest_store.worker_principal() != &principal
    {
        return Err(RootlessSetupError::PlanInvalid);
    }

    let existing = manifest_store
        .read_optional_for_setup()
        .map_err(|_| RootlessSetupError::PlanInvalid)?;
    let recorded_host_key_fingerprint = existing
        .as_ref()
        .and_then(|manifest| manifest.ssh.as_ref())
        .and_then(|ssh| ssh.host_key_fingerprint.as_deref())
        .map(str::to_owned);
    let catalog =
        production_rootless_catalog(&effective).map_err(|_| RootlessSetupError::ProbeFailed)?;
    let observed = catalog.observe();
    let desired =
        rootless_baseline_desired_state(&effective).map_err(|_| RootlessSetupError::PlanInvalid)?;
    let capability_plan =
        SetupPlan::compute(&observed, &desired).map_err(|_| RootlessSetupError::PlanInvalid)?;
    let mut components = vec!["directories".to_owned(); actions.len()];
    if !effective.authorized_public_keys().is_empty() {
        let ssh_actions = match candidate_ssh_directory {
            CandidateSshDirectory::Canonical => action::current_user_ssh_action_plan(
                principal.clone(),
                effective.authorized_public_keys(),
            ),
            #[cfg(test)]
            CandidateSshDirectory::Exact(directory) => {
                action::current_user_ssh_action_plan_for_test(
                    principal.clone(),
                    directory,
                    effective.authorized_public_keys(),
                )
            }
            #[cfg(test)]
            CandidateSshDirectory::Unavailable => return Err(RootlessSetupError::PlanInvalid),
        }
        .map_err(|_| RootlessSetupError::PlanInvalid)?;
        components.extend(std::iter::repeat_n(
            "ssh-server".to_owned(),
            ssh_actions.len(),
        ));
        actions.extend(ssh_actions);
    }
    for (component, action) in capability_plan.into_component_actions() {
        components.push(component);
        actions.push(action);
    }

    let base = rootless_manifest_base(existing, &effective, &observed)?;
    let candidate = match candidate_layout {
        CandidateLayout::Canonical => {
            manifest::CurrentUserWorkerManifestCandidate::derive(&base, &principal)
        }
        #[cfg(test)]
        CandidateLayout::Exact(layout) => {
            manifest::CurrentUserWorkerManifestCandidate::derive_with_layout_for_test(
                &base, &principal, &layout,
            )
        }
    }
    .map_err(|_| RootlessSetupError::PlanInvalid)?;
    let draft = candidate.into_draft();
    if !effective.authorized_public_keys().is_empty() || recorded_host_key_fingerprint.is_some() {
        let transport = draft
            .transport
            .as_ref()
            .ok_or(RootlessSetupError::PlanInvalid)?;
        let port = transport.port.unwrap_or(22);
        let discovery_pending = candidate_host_key
            .discover(
                &transport.host,
                port,
                recorded_host_key_fingerprint.as_deref(),
            )
            .is_none();
        components.push("ssh-server".to_owned());
        actions.push(enrollment_card_action(discovery_pending)?);
    }
    receipt_store
        .read_snapshot()
        .map_err(map_receipt_preflight_error)?;
    let plan_items = build_plan_items(&components, &actions)?;

    Ok(RootlessSetupPlan {
        effective,
        plan_items,
        actions,
        draft,
        receipt_store,
        manifest_store,
        candidate_host_key,
    })
}

fn enrollment_card_after_apply(
    effective: &EffectiveRootlessSetup,
    draft: &mut manifest::MachineManifestDraft,
    candidate_host_key: &CandidateHostKey,
) -> Option<EnrollmentCard> {
    let readiness = production_rootless_ssh_readiness(effective).ok();
    refresh_ssh_manifest(draft, readiness.as_ref());
    if !matches!(readiness, Some(ProbeStatus::Present { healthy: true, .. })) {
        return None;
    }
    let should_emit = !effective.authorized_public_keys().is_empty()
        || draft
            .ssh
            .as_ref()
            .and_then(|ssh| ssh.host_key_fingerprint.as_ref())
            .is_some();
    if !should_emit {
        return None;
    }
    let transport = draft.transport.as_ref()?;
    let host = transport.host.clone();
    let user = transport.user.clone()?;
    let port = transport.port.unwrap_or(22);
    let expected_fingerprint = draft
        .ssh
        .as_ref()
        .and_then(|ssh| ssh.host_key_fingerprint.as_deref());
    let host_key = candidate_host_key.discover(&host, port, expected_fingerprint)?;
    let card = EnrollmentCard::new(&draft.name, &host, &user, port, &host_key).ok()?;
    let ssh = draft.ssh.as_mut()?;
    ssh.host_key_fingerprint = Some(host_key.fingerprint().to_owned());
    Some(card)
}

fn refresh_ssh_manifest(
    draft: &mut manifest::MachineManifestDraft,
    readiness: Option<&ProbeStatus>,
) {
    let Some(ssh) = draft.ssh.as_mut() else {
        return;
    };
    match readiness {
        Some(ProbeStatus::Present { healthy, .. }) => {
            ssh.installed = Some(true);
            ssh.server = Some(true);
            ssh.public_key_auth = Some(*healthy);
        }
        Some(ProbeStatus::Absent) => {
            ssh.installed = Some(false);
            ssh.server = Some(false);
            ssh.public_key_auth = Some(false);
        }
        Some(ProbeStatus::Broken { .. }) => {
            ssh.installed = Some(true);
            ssh.server = Some(true);
            ssh.public_key_auth = Some(false);
        }
        Some(ProbeStatus::TailscalePresent { .. })
        | Some(ProbeStatus::Unknowable { .. })
        | None => {
            ssh.installed = None;
            ssh.server = None;
            ssh.public_key_auth = None;
        }
    }
}

fn enrollment_card_action(pending: bool) -> Result<Action, RootlessSetupError> {
    let action_id =
        ActionName::parse("ssh.enrollment-card").map_err(|_| RootlessSetupError::PlanInvalid)?;
    let description = if pending {
        "Verify that the SSH server is listening locally, then rerun setup to record its host-key fingerprint and enrollment card."
    } else {
        "Verify and record the live SSH host key for the enrollment card."
    };
    let description =
        ActionDescription::new(description).map_err(|_| RootlessSetupError::PlanInvalid)?;
    Ok(Action::planned(
        action_id,
        description,
        Privilege::None,
        if pending {
            PlanOperation::NeedsHuman
        } else {
            PlanOperation::Done
        },
    ))
}

fn reconcile_enrollment_card_action(
    actions: &mut [Action],
    plan_items: &mut [RootlessSetupPlanItem],
    pending: bool,
) -> Result<bool, RootlessSetupError> {
    let Some(action) = actions
        .iter_mut()
        .find(|action| action.name().as_str() == "ssh.enrollment-card")
    else {
        return Ok(false);
    };
    let currently_pending = matches!(
        action
            .check()
            .map_err(|_| RootlessSetupError::ProbeFailed)?,
        ActionCheck::NeedsHuman(_)
    );
    if currently_pending == pending {
        return Ok(false);
    }
    *action = enrollment_card_action(pending)?;
    let item = plan_items
        .iter_mut()
        .find(|item| item.action_id() == "ssh.enrollment-card")
        .ok_or(RootlessSetupError::PlanInvalid)?;
    let check = action
        .check()
        .map_err(|_| RootlessSetupError::ProbeFailed)?;
    item.operation = displayed_operation(action.plan_operation(), &check);
    item.description = action.describe().as_str().to_owned();
    Ok(true)
}

pub(crate) fn apply_rootless_setup(
    prepared: RootlessSetupPlan,
) -> Result<RootlessSetupOutcome, RootlessSetupError> {
    let RootlessSetupPlan {
        effective,
        mut plan_items,
        mut actions,
        mut draft,
        receipt_store,
        manifest_store,
        candidate_host_key,
    } = prepared;
    let fail_on_pending = effective.fail_on_pending();
    let mut metadata = ReceiptMetadataSource::system();
    let mut report = action::apply_plan_with_journal(&mut actions, &receipt_store, &mut metadata)
        .map_err(map_apply_error)?;
    let mut results = report.results().to_vec();
    let enrollment_card = enrollment_card_after_apply(&effective, &mut draft, &candidate_host_key);
    if reconcile_enrollment_card_action(&mut actions, &mut plan_items, enrollment_card.is_none())? {
        report = action::apply_plan_with_journal(&mut actions, &receipt_store, &mut metadata)
            .map_err(map_apply_error)?;
        merge_action_results(&mut results, report.results());
    }
    // The card marker is virtual plan/pending state. It performs no standalone
    // mutation, so do not present its journal transition as an execution result.
    results.retain(|result| result.action_id() != "ssh.enrollment-card");
    let mut retry_count = 0;
    let machine_id = loop {
        match pending::publish_manifest(
            &manifest_store,
            &receipt_store,
            &mut draft,
            report.completion(),
            &mut metadata,
        ) {
            Ok(machine_id) => break machine_id,
            Err(error)
                if error.is_stale_completion_witness()
                    && retry_count < CONCURRENT_PUBLICATION_RETRIES =>
            {
                retry_count += 1;
                report =
                    action::apply_plan_with_journal(&mut actions, &receipt_store, &mut metadata)
                        .map_err(map_apply_error)?;
                merge_action_results(&mut results, report.results());
            }
            Err(error) => return Err(map_publication_error(error)),
        }
    };
    let pending = report
        .pending()
        .iter()
        .map(|action| RootlessPendingResult {
            action_id: action.id().as_str().to_owned(),
            severity: pending_severity(action.severity()),
            message: action.needs_human().instructions().as_str().to_owned(),
        })
        .collect();
    let outcome = RootlessSetupOutcome {
        plan_items,
        results,
        pending,
        manifest_path: manifest_store.path().to_path_buf(),
        receipt_path: receipt_store.path().to_path_buf(),
        security_caveat: CURRENT_USER_CAVEAT,
        machine_id,
        enrollment_card,
    };
    let policy = PendingPolicy::new(fail_on_pending)
        .evaluate(chrono::Utc::now(), report.completion())
        .map_err(|_| RootlessSetupError::ApplyFailed)?;
    if policy.exit_code() != crate::output::StyrnExit::Success {
        Err(RootlessSetupError::NeedsHuman(Box::new(outcome)))
    } else {
        Ok(outcome)
    }
}

fn merge_action_results(
    results: &mut Vec<ActionExecutionResult>,
    latest: &[ActionExecutionResult],
) {
    for candidate in latest {
        if let Some(existing) = results
            .iter_mut()
            .find(|existing| existing.action_id() == candidate.action_id())
        {
            if execution_status_rank(candidate.status()) > execution_status_rank(existing.status())
            {
                *existing = candidate.clone();
            }
        } else {
            results.push(candidate.clone());
        }
    }
}

const fn execution_status_rank(status: action::ActionExecutionStatus) -> u8 {
    match status {
        action::ActionExecutionStatus::Unchanged => 0,
        action::ActionExecutionStatus::Pending => 1,
        action::ActionExecutionStatus::Applied => 2,
        action::ActionExecutionStatus::Recovered => 3,
    }
}

fn map_publication_error(error: pending::PendingError) -> RootlessSetupError {
    RootlessSetupError::OperationFailed {
        error_code: error.error_code(),
        context: RootlessFailureContext {
            phase: "publication",
            action_id: "manifest.publish".to_owned(),
            cause_category: error.safe_cause(),
            remediation: "verify the user state directory and retry setup",
        },
    }
}

fn map_apply_error(error: action::ApplyPlanError) -> RootlessSetupError {
    let action_id = error
        .action_id()
        .map(|action| action.as_str())
        .unwrap_or("receipt.journal")
        .to_owned();
    RootlessSetupError::OperationFailed {
        error_code: error.error_code(),
        context: RootlessFailureContext {
            phase: "execution",
            action_id,
            cause_category: error.safe_cause(),
            remediation: "correct the reported setup operation posture and retry setup",
        },
    }
}

fn build_plan_items(
    components: &[String],
    actions: &[Action],
) -> Result<Vec<RootlessSetupPlanItem>, RootlessSetupError> {
    if components.len() != actions.len() {
        return Err(RootlessSetupError::PlanInvalid);
    }
    components
        .iter()
        .zip(actions)
        .map(|(component, action)| {
            let check = action
                .check()
                .map_err(|_| RootlessSetupError::ProbeFailed)?;
            Ok(RootlessSetupPlanItem {
                action_id: action.name().as_str().to_owned(),
                component: component.clone(),
                operation: displayed_operation(action.plan_operation(), &check),
                privilege: privilege_name(action.privilege()),
                description: action.describe().as_str().to_owned(),
                scope: "user",
                role: "worker",
                account: "current-user",
                security_caveat: CURRENT_USER_CAVEAT,
            })
        })
        .collect()
}

fn displayed_operation(operation: PlanOperation, check: &ActionCheck) -> &'static str {
    match check {
        ActionCheck::Done => "done",
        ActionCheck::NeedsHuman(_) => "needs_human",
        ActionCheck::Todo => match operation {
            PlanOperation::Create => "create",
            PlanOperation::Reconfigure => "reconfigure",
            PlanOperation::Remove => "remove",
            PlanOperation::Done => "done",
            PlanOperation::NeedsHuman => "needs_human",
            PlanOperation::Skipped => "skipped",
        },
    }
}

const fn privilege_name(privilege: Privilege) -> &'static str {
    match privilege {
        Privilege::None => "none",
        Privilege::Root => "root",
        Privilege::Admin => "admin",
    }
}

const fn pending_severity(severity: PendingSeverity) -> &'static str {
    match severity {
        PendingSeverity::Info => "info",
        PendingSeverity::Warning => "warning",
        PendingSeverity::Error => "error",
    }
}

fn rootless_manifest_base(
    existing: Option<manifest::MachineManifest>,
    effective: &EffectiveRootlessSetup,
    observed: &ObservedState,
) -> Result<manifest::MachineManifestDraft, RootlessSetupError> {
    let hostname = sysinfo::System::host_name()
        .filter(|hostname| super::validate_probe_static_text(hostname) && !hostname.is_empty())
        .ok_or(RootlessSetupError::ProbeFailed)?;
    let operating_system = native_operating_system();
    let architecture = native_architecture()?;
    let mut draft = existing
        .map(manifest::MachineManifest::without_machine_id)
        .unwrap_or_else(|| manifest::MachineManifestDraft {
            schema_version: 1,
            name: hostname.clone(),
            roles: vec![manifest::MachineRole::Worker],
            platform: manifest::Platform {
                os: operating_system.clone(),
                arch: architecture.clone(),
                hostname: hostname.clone(),
                headless: None,
            },
            installation: Some(manifest::Installation {
                scope: platform::InstallationScope::User,
            }),
            worker_identity: None,
            transport: Some(manifest::Transport {
                kind: manifest::TransportKind::Ssh,
                host: hostname.clone(),
                port: Some(22),
                user: None,
            }),
            paths: manifest::Paths {
                root: String::new(),
                repos: String::new(),
                jobs: String::new(),
                cache: String::new(),
                artifacts: String::new(),
                logs: String::new(),
            },
            controller: None,
            worker: None,
            resources: None,
            capabilities: None,
            scheduling: None,
            tailscale: None,
            ssh: None,
            herdr: None,
            agents: None,
            toolchains: None,
            caches: None,
            install: None,
            desktop: None,
            pending_actions: None,
        });
    let resource_policy = draft
        .resources
        .take()
        .and_then(|resources| resources.policy);
    let recorded_host_key_fingerprint = draft
        .ssh
        .as_ref()
        .and_then(|ssh| ssh.host_key_fingerprint.clone());
    let logical_cpus = std::thread::available_parallelism()
        .ok()
        .and_then(|count| u64::try_from(count.get()).ok());
    let system = sysinfo::System::new_all();
    draft.schema_version = 1;
    draft.name = effective.machine_name().unwrap_or(&hostname).to_owned();
    draft.roles = vec![manifest::MachineRole::Worker];
    draft.platform = manifest::Platform {
        os: operating_system,
        arch: architecture,
        hostname: hostname.clone(),
        headless: None,
    };
    draft.installation = Some(manifest::Installation {
        scope: platform::InstallationScope::User,
    });
    draft.worker_identity = None;
    draft.transport = Some(manifest::Transport {
        kind: manifest::TransportKind::Ssh,
        host: hostname,
        port: Some(22),
        user: None,
    });
    draft.controller = None;
    draft.worker = Some(manifest::Worker {
        enabled: Some(true),
        accept_jobs: Some(probe_is_healthy(observed, "service.styrnd")),
    });
    draft.resources = Some(manifest::Resources {
        detected: Some(manifest::DetectedResources {
            logical_cpus,
            memory_bytes: Some(system.total_memory()),
            disk_bytes: None,
        }),
        policy: resource_policy,
    });
    draft.capabilities = Some(
        effective
            .selected_component_names()
            .map(|component| {
                (
                    component.to_owned(),
                    probe_is_healthy(observed, probe_id_for_component(component)),
                )
            })
            .collect::<BTreeMap<_, _>>(),
    );
    draft.ssh = component_selected(effective, "ssh-server").then(|| manifest::Ssh {
        installed: Some(probe_is_present(observed, "service.sshd")),
        server: Some(probe_is_present(observed, "service.sshd")),
        public_key_auth: Some(probe_is_healthy(observed, "service.sshd")),
        host_key_fingerprint: recorded_host_key_fingerprint,
    });
    draft.tailscale = component_selected(effective, "tailscale").then(|| {
        let posture = observed_tailscale_posture(observed);
        manifest::Tailscale {
            installed: Some(probe_is_present(observed, "network.tailscale")),
            mode: posture.map(|posture| match posture.mode {
                probe::ObservedTailscaleMode::Gui => manifest::TailscaleMode::Gui,
                probe::ObservedTailscaleMode::Tailscaled => manifest::TailscaleMode::Tailscaled,
                probe::ObservedTailscaleMode::Service => manifest::TailscaleMode::Service,
            }),
            unattended: posture.map(|posture| posture.unattended),
        }
    });
    if component_selected(effective, "herdr") {
        let enabled = draft
            .herdr
            .as_ref()
            .and_then(|herdr| herdr.enabled)
            .or(Some(true));
        draft.herdr = Some(manifest::Herdr {
            installed: Some(probe_is_healthy(observed, "tool.herdr")),
            enabled,
            session: None,
            autostart: None,
        });
    }
    draft.pending_actions = None;
    Ok(draft)
}

fn component_selected(effective: &EffectiveRootlessSetup, expected: &str) -> bool {
    effective
        .selected_component_names()
        .any(|component| component == expected)
}

fn probe_is_present(observed: &ObservedState, id: &str) -> bool {
    observed.setup_observations().any(|observation| {
        observation.descriptor().id().as_str() == id
            && matches!(
                observation.status(),
                ProbeStatus::Present { .. } | ProbeStatus::TailscalePresent { .. }
            )
    })
}

fn probe_is_healthy(observed: &ObservedState, id: &str) -> bool {
    observed.setup_observations().any(|observation| {
        observation.descriptor().id().as_str() == id
            && matches!(
                observation.status(),
                ProbeStatus::Present { healthy: true, .. }
                    | ProbeStatus::TailscalePresent { healthy: true, .. }
            )
    })
}

fn observed_tailscale_posture(observed: &ObservedState) -> Option<probe::ObservedTailscalePosture> {
    observed.setup_observations().find_map(|observation| {
        if observation.descriptor().id().as_str() != "network.tailscale" {
            return None;
        }
        match observation.status() {
            ProbeStatus::TailscalePresent { posture, .. } => Some(*posture),
            _ => None,
        }
    })
}

fn probe_id_for_component(component: &str) -> &'static str {
    match component {
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
    }
}

fn native_operating_system() -> manifest::OperatingSystem {
    #[cfg(target_os = "linux")]
    return manifest::OperatingSystem::Linux;
    #[cfg(target_os = "macos")]
    return manifest::OperatingSystem::Macos;
    #[cfg(target_os = "windows")]
    return manifest::OperatingSystem::Windows;
}

fn native_architecture() -> Result<manifest::Architecture, RootlessSetupError> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(manifest::Architecture::X86_64),
        "aarch64" => Ok(manifest::Architecture::Aarch64),
        _ => Err(RootlessSetupError::ProbeFailed),
    }
}

fn map_receipt_preflight_error(_: super::receipt::ReceiptStoreError) -> RootlessSetupError {
    RootlessSetupError::ReceiptConflict
}

#[cfg(test)]
mod tests {
    use super::super::{
        action::{ActionExecutionStatus, ActionParameters, Privilege},
        apply_rootless_setup,
        config::effective_from_interactive_answers,
        prepare_rootless_setup_for_test, prepare_rootless_setup_for_test_with_ssh_directory,
        prepare_rootless_setup_for_test_with_ssh_directory_and_host_key, RootlessSetupError,
    };
    use crate::{manifest, platform};
    use std::{
        ffi::OsString,
        fs,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    const CAVEAT: &str = "Current-user mode provides no OS-account isolation, no controller-credential isolation, and no same-user Styrn-state integrity boundary.";

    struct Fixture {
        root: PathBuf,
        layout: platform::WorkerDirectoryLayout,
        principal: platform::WorkerPrincipal,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::current_dir()
                .unwrap()
                .join("target")
                .join(format!(
                    "styrn-rootless-orchestrator-{label}-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            fs::create_dir_all(&root).unwrap();
            let principal = platform::resolve_current_worker_principal().unwrap();
            let layout = platform::worker_directory_layout_for_test(
                platform::InstallationScope::User,
                principal.clone(),
                root.join("data").join("styrn"),
                Some(root.clone()),
            );
            Self {
                root,
                layout,
                principal,
            }
        }

        fn context(&self) -> platform::SetupExecutionContext {
            platform::SetupExecutionContext::new_for_test(
                platform::SetupHostPrivilege::Ordinary,
                self.principal.clone(),
            )
        }

        fn receipt_path(&self) -> PathBuf {
            self.root.join("state").join("styrn").join("receipt.json")
        }

        fn manifest_path(&self) -> PathBuf {
            self.root.join("config").join("styrn").join("machine.toml")
        }

        fn receipt_store(&self) -> crate::setup::receipt::ReceiptStore {
            crate::setup::receipt::ReceiptStore::new_user_for_test_with_worker_layout(
                self.receipt_path(),
                self.layout.clone(),
            )
        }

        fn manifest_store(&self) -> manifest::MachineManifestStore {
            manifest::MachineManifestStore::new_user_with_worker_layout_for_test(
                self.manifest_path(),
                self.principal.clone(),
                &self.layout,
            )
            .unwrap()
        }

        fn prepare(
            &self,
            effective: crate::setup::EffectiveRootlessSetup,
        ) -> Result<crate::setup::RootlessSetupPlan, RootlessSetupError> {
            prepare_rootless_setup_for_test(
                effective,
                self.context(),
                self.layout.clone(),
                self.receipt_store(),
                self.manifest_store(),
            )
        }

        fn effective(&self, name: Option<&str>) -> crate::setup::EffectiveRootlessSetup {
            effective_from_interactive_answers("worker".to_owned(), None, name.map(str::to_owned))
                .unwrap()
        }

        fn strict_effective(&self) -> crate::setup::EffectiveRootlessSetup {
            let config = self.root.join("strict-setup.toml");
            fs::write(
                &config,
                "schema_version = 1\n[pending_policy]\nfail_on_pending = true\n",
            )
            .unwrap();
            let parsed = crate::cli::Cli::try_parse_with_facts(
                [
                    OsString::from("styrn"),
                    OsString::from("setup"),
                    OsString::from("--config"),
                    config.into_os_string(),
                ]
                .into(),
                crate::cli::CliFacts::for_test(false, false, false),
            )
            .unwrap();
            crate::setup::load_effective_rootless_setup(&parsed.setup_request().unwrap()).unwrap()
        }

        fn effective_with_authorized_key(&self) -> crate::setup::EffectiveRootlessSetup {
            let parsed = crate::cli::Cli::try_parse_with_facts(
                [
                    OsString::from("styrn"),
                    OsString::from("setup"),
                    OsString::from("--authorized-keys"),
                    OsString::from(VALID_CONTROLLER_KEY),
                ]
                .into(),
                crate::cli::CliFacts::for_test(false, false, false),
            )
            .unwrap();
            crate::setup::load_effective_rootless_setup(&parsed.setup_request().unwrap()).unwrap()
        }

        fn ssh_directory(&self) -> PathBuf {
            self.root.join("profile").join(".ssh")
        }

        fn pending_intent_path(&self) -> PathBuf {
            self.receipt_path()
                .parent()
                .unwrap()
                .join(".receipt.json.pending-publication.json")
        }

        fn harden_user_file(&self, path: &std::path::Path, bytes: &[u8]) {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let owner = platform::ManifestOwner::User;
            let trusted = path.parent().unwrap().parent().unwrap();
            platform::harden_manifest_directory(trusted, owner, &self.principal).unwrap();
            platform::harden_manifest_directory(path.parent().unwrap(), owner, &self.principal)
                .unwrap();
            fs::write(path, bytes).unwrap();
            platform::harden_manifest_file(path, owner, &self.principal).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    struct SnapshotGuard;

    impl SnapshotGuard {
        fn absent() -> Self {
            use platform::{BaselineProbeKind as Kind, BaselineProbeSnapshot as Snapshot};
            platform::set_baseline_probe_snapshots_for_test([
                (Kind::SshServer, Snapshot::Absent),
                (Kind::Tailscale, Snapshot::Absent),
                (Kind::Git, Snapshot::Absent),
                (Kind::Styrnd, Snapshot::Absent),
                (Kind::SleepPolicy, Snapshot::Absent),
                (Kind::Deferred, Snapshot::Absent),
            ]);
            Self
        }

        fn healthy() -> Self {
            use platform::{BaselineProbeKind as Kind, BaselineProbeSnapshot as Snapshot};
            platform::set_baseline_probe_snapshots_for_test([
                (
                    Kind::SshServer,
                    Snapshot::Present {
                        version: None,
                        healthy: true,
                    },
                ),
                (
                    Kind::Tailscale,
                    Snapshot::TailscalePresent {
                        version: Some("1.90.0".to_owned()),
                        healthy: true,
                        posture: platform::BaselineTailscalePosture {
                            mode: platform::BaselineTailscaleMode::Tailscaled,
                            persistent: true,
                            unattended: true,
                        },
                    },
                ),
                (
                    Kind::Git,
                    Snapshot::Present {
                        version: Some("2.51.0".to_owned()),
                        healthy: true,
                    },
                ),
                (
                    Kind::Styrnd,
                    Snapshot::Present {
                        version: Some("0.1.0".to_owned()),
                        healthy: true,
                    },
                ),
                (
                    Kind::SleepPolicy,
                    Snapshot::Present {
                        version: None,
                        healthy: true,
                    },
                ),
                (
                    Kind::Deferred,
                    Snapshot::Present {
                        version: None,
                        healthy: true,
                    },
                ),
            ]);
            platform::set_rootless_ssh_transport_probe_snapshot_for_test(Snapshot::Present {
                version: None,
                healthy: true,
            });
            Self
        }

        fn windows_service_without_unattended() -> Self {
            use platform::{BaselineProbeKind as Kind, BaselineProbeSnapshot as Snapshot};
            let guard = Self::healthy();
            platform::set_baseline_probe_snapshots_for_test([(
                Kind::Tailscale,
                Snapshot::TailscalePresent {
                    version: Some("1.90.0".to_owned()),
                    healthy: false,
                    posture: platform::BaselineTailscalePosture {
                        mode: platform::BaselineTailscaleMode::Service,
                        persistent: true,
                        unattended: false,
                    },
                },
            )]);
            guard
        }
    }

    impl Drop for SnapshotGuard {
        fn drop(&mut self) {
            platform::clear_baseline_probe_snapshots_for_test();
            platform::clear_rootless_ssh_transport_probe_snapshot_for_test();
        }
    }

    const VALID_CONTROLLER_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f styrn-controller";
    const HOST_KEY_FINGERPRINT: &str = "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA";

    #[test]
    fn enrollment_card_names_the_exact_host_user_and_verified_fingerprint() {
        let host_key = verified_host_key();

        let card =
            super::EnrollmentCard::new("worker-01", "worker-01.example", "alex", 22, &host_key)
                .unwrap();

        assert_eq!(card.name(), "worker-01");
        assert_eq!(card.host(), "worker-01.example");
        assert_eq!(card.user(), "alex");
        assert_eq!(card.fingerprint(), HOST_KEY_FINGERPRINT);
        assert_eq!(
            card.command(),
            format!(
                "styrn host enroll worker-01.example --user alex --fingerprint {HOST_KEY_FINGERPRINT}"
            )
        );
        assert!(card.integrity_guidance().contains("worker's own console"));
        assert!(card.controller_recovery().contains("styrn controller init"));
        assert!(!card.command().contains("ssh-ed25519"));
    }

    #[test]
    fn enrollment_card_command_is_the_public_noninteractive_enroll_surface() {
        let host_key = verified_host_key();
        let card = super::EnrollmentCard::new(
            "friendly-worker-name",
            "worker-01.example",
            "alex",
            22,
            &host_key,
        )
        .unwrap();
        let arguments = card
            .command()
            .split_ascii_whitespace()
            .map(OsString::from)
            .collect::<Vec<_>>();

        let parsed = crate::cli::Cli::try_parse_with_facts(
            arguments,
            crate::cli::CliFacts::for_test(false, false, false),
        )
        .unwrap();

        assert_eq!(
            parsed.host_action(),
            Some(crate::cli::HostAction::Enroll {
                host: "worker-01.example".to_owned(),
                user: "alex".to_owned(),
                fingerprint: Some(HOST_KEY_FINGERPRINT.to_owned()),
            })
        );
        assert_eq!(card.name(), "friendly-worker-name");
        assert_ne!(card.name(), card.host());
    }

    #[test]
    fn successful_setup_records_and_returns_the_verified_enrollment_card() {
        let fixture = Fixture::new("enrollment-card");
        let _snapshots = SnapshotGuard::healthy();
        fs::create_dir_all(fixture.ssh_directory().parent().unwrap()).unwrap();
        let prepared = prepare_rootless_setup_for_test_with_ssh_directory_and_host_key(
            fixture.effective_with_authorized_key(),
            fixture.context(),
            fixture.layout.clone(),
            fixture.receipt_store(),
            fixture.manifest_store(),
            fixture.ssh_directory(),
            verified_host_key(),
        )
        .unwrap();

        let outcome = apply_rootless_setup(prepared).unwrap();
        let card = outcome
            .enrollment_card()
            .expect("a verified ready SSH transport must produce an enrollment card");
        assert_eq!(card.user(), fixture.principal.name());
        assert_eq!(card.fingerprint(), HOST_KEY_FINGERPRINT);
        assert!(card.command().contains(" --user "));
        assert!(card.command().contains(" --fingerprint SHA256:"));
        assert_eq!(
            outcome
                .plan_items()
                .iter()
                .find(|item| item.action_id() == "ssh.enrollment-card")
                .unwrap()
                .operation(),
            "done"
        );
        assert!(outcome
            .results()
            .iter()
            .all(|result| result.action_id() != "ssh.enrollment-card"));

        let manifest = fixture.manifest_store().read().unwrap().manifest;
        assert_eq!(
            manifest
                .ssh
                .as_ref()
                .and_then(|ssh| ssh.host_key_fingerprint.as_deref()),
            Some(HOST_KEY_FINGERPRINT)
        );
    }

    #[test]
    fn host_key_discovery_failure_keeps_useful_state_and_records_pending_without_a_card() {
        let fixture = Fixture::new("enrollment-card-discovery-failure");
        let _snapshots = SnapshotGuard::healthy();
        fs::create_dir_all(fixture.ssh_directory().parent().unwrap()).unwrap();
        let outcome = prepare_rootless_setup_for_test_with_ssh_directory(
            fixture.effective_with_authorized_key(),
            fixture.context(),
            fixture.layout.clone(),
            fixture.receipt_store(),
            fixture.manifest_store(),
            fixture.ssh_directory(),
        )
        .and_then(apply_rootless_setup)
        .unwrap();

        assert!(outcome.enrollment_card().is_none());
        assert!(outcome
            .pending()
            .iter()
            .any(|pending| pending.action_id() == "ssh.enrollment-card"));
        assert_eq!(
            outcome
                .plan_items()
                .iter()
                .find(|item| item.action_id() == "ssh.enrollment-card")
                .unwrap()
                .operation(),
            "needs_human"
        );
        assert!(fixture.manifest_path().is_file());
        assert_eq!(
            fs::read_to_string(fixture.ssh_directory().join("authorized_keys")).unwrap(),
            format!("{VALID_CONTROLLER_KEY}\n")
        );
        let manifest = fixture.manifest_store().read().unwrap().manifest;
        assert!(manifest
            .pending_actions
            .as_ref()
            .is_some_and(|pending| pending.iter().any(|item| item.id == "ssh.enrollment-card")));
        assert!(manifest
            .ssh
            .as_ref()
            .and_then(|ssh| ssh.host_key_fingerprint.as_ref())
            .is_none());
    }

    #[test]
    fn transport_only_readiness_never_emits_a_card_without_key_login_readiness() {
        let fixture = Fixture::new("enrollment-card-full-readiness");
        let _snapshots = SnapshotGuard::healthy();
        platform::set_baseline_probe_snapshots_for_test([(
            platform::BaselineProbeKind::SshServer,
            platform::BaselineProbeSnapshot::Present {
                version: None,
                healthy: false,
            },
        )]);
        fs::create_dir_all(fixture.ssh_directory().parent().unwrap()).unwrap();

        let outcome = prepare_rootless_setup_for_test_with_ssh_directory_and_host_key(
            fixture.effective_with_authorized_key(),
            fixture.context(),
            fixture.layout.clone(),
            fixture.receipt_store(),
            fixture.manifest_store(),
            fixture.ssh_directory(),
            verified_host_key(),
        )
        .and_then(apply_rootless_setup)
        .unwrap();

        assert!(outcome.enrollment_card().is_none());
        assert!(outcome
            .pending()
            .iter()
            .any(|pending| pending.action_id() == "ssh.enrollment-card"));
        let manifest = fixture.manifest_store().read().unwrap().manifest;
        let ssh = manifest.ssh.unwrap();
        assert_eq!(ssh.public_key_auth, Some(false));
        assert!(ssh.host_key_fingerprint.is_none());
    }

    #[test]
    fn transient_discovery_failure_preserves_the_recorded_fingerprint_on_zero_arg_rerun() {
        let fixture = Fixture::new("enrollment-card-fingerprint-rerun");
        let _snapshots = SnapshotGuard::healthy();
        fs::create_dir_all(fixture.ssh_directory().parent().unwrap()).unwrap();
        let first = prepare_rootless_setup_for_test_with_ssh_directory_and_host_key(
            fixture.effective_with_authorized_key(),
            fixture.context(),
            fixture.layout.clone(),
            fixture.receipt_store(),
            fixture.manifest_store(),
            fixture.ssh_directory(),
            verified_host_key(),
        )
        .and_then(apply_rootless_setup)
        .unwrap();
        assert!(first.enrollment_card().is_some());

        let healthy_rerun = prepare_rootless_setup_for_test_with_ssh_directory_and_host_key(
            fixture.effective(None),
            fixture.context(),
            fixture.layout.clone(),
            fixture.receipt_store(),
            fixture.manifest_store(),
            fixture.ssh_directory(),
            verified_host_key(),
        )
        .and_then(apply_rootless_setup)
        .unwrap();
        assert_eq!(
            healthy_rerun
                .enrollment_card()
                .map(super::EnrollmentCard::fingerprint),
            Some(HOST_KEY_FINGERPRINT)
        );

        let rerun = fixture
            .prepare(fixture.effective(None))
            .and_then(apply_rootless_setup)
            .unwrap();

        assert!(rerun.enrollment_card().is_none());
        assert!(rerun
            .pending()
            .iter()
            .any(|pending| pending.action_id() == "ssh.enrollment-card"));
        assert_eq!(
            fixture
                .manifest_store()
                .read()
                .unwrap()
                .manifest
                .ssh
                .and_then(|ssh| ssh.host_key_fingerprint),
            Some(HOST_KEY_FINGERPRINT.to_owned())
        );
    }

    fn verified_host_key() -> crate::transport::PinnedHostKey {
        crate::transport::PinnedHostKey::from_parts(
            "ssh-ed25519",
            "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f",
            HOST_KEY_FINGERPRINT,
        )
        .unwrap()
    }

    #[test]
    fn configured_controller_key_is_a_journaled_current_user_action_and_reruns_unchanged() {
        let fixture = Fixture::new("authorized-key");
        let _snapshots = SnapshotGuard::healthy();
        fs::create_dir_all(fixture.ssh_directory().parent().unwrap()).unwrap();
        let effective = fixture.effective_with_authorized_key();
        let prepared = prepare_rootless_setup_for_test_with_ssh_directory(
            effective,
            fixture.context(),
            fixture.layout.clone(),
            fixture.receipt_store(),
            fixture.manifest_store(),
            fixture.ssh_directory(),
        )
        .unwrap();

        let key_item = prepared
            .plan_items()
            .iter()
            .find(|item| item.action_id() == "ssh.authorized-keys")
            .expect("configured controller keys must produce one concrete action");
        assert_eq!(key_item.component(), "ssh-server");
        assert_eq!(key_item.operation(), "create");
        assert_eq!(key_item.privilege(), "none");

        let first = apply_rootless_setup(prepared).unwrap();
        let authorized_keys = fixture.ssh_directory().join("authorized_keys");
        assert_eq!(
            fs::read_to_string(&authorized_keys).unwrap(),
            format!("{VALID_CONTROLLER_KEY}\n")
        );
        assert!(first
            .results()
            .iter()
            .any(|result| result.action_id() == "ssh.authorized-keys"
                && result.status() == ActionExecutionStatus::Applied));
        let receipt: serde_json::Value = serde_json::from_slice(
            &fixture
                .receipt_store()
                .read_snapshot()
                .unwrap()
                .to_json()
                .unwrap(),
        )
        .unwrap();
        let rendered_receipt = receipt.to_string();
        assert!(!rendered_receipt.contains(VALID_CONTROLLER_KEY));
        let key_entry = receipt["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["action"]["parameters"]["action_id"] == "ssh.authorized-keys")
            .expect("the key-file mutation must be journaled");
        assert_eq!(key_entry["privilege_used"], "none");
        assert_eq!(key_entry["files_created"].as_array().unwrap().len(), 1);
        assert_eq!(key_entry["files_modified"].as_array().unwrap().len(), 0);
        let before = fs::read(&authorized_keys).unwrap();

        let rerun = prepare_rootless_setup_for_test_with_ssh_directory(
            fixture.effective_with_authorized_key(),
            fixture.context(),
            fixture.layout.clone(),
            fixture.receipt_store(),
            fixture.manifest_store(),
            fixture.ssh_directory(),
        )
        .and_then(apply_rootless_setup)
        .unwrap();
        assert_eq!(fs::read(&authorized_keys).unwrap(), before);
        assert!(rerun
            .results()
            .iter()
            .any(|result| result.action_id() == "ssh.authorized-keys"
                && result.status() == ActionExecutionStatus::Unchanged));
    }

    #[test]
    fn rerun_after_the_journaled_ssh_directory_step_finishes_key_publication() {
        let fixture = Fixture::new("authorized-key-interruption");
        let _snapshots = SnapshotGuard::healthy();
        fs::create_dir_all(fixture.ssh_directory().parent().unwrap()).unwrap();
        let mut prepared = prepare_rootless_setup_for_test_with_ssh_directory(
            fixture.effective_with_authorized_key(),
            fixture.context(),
            fixture.layout.clone(),
            fixture.receipt_store(),
            fixture.manifest_store(),
            fixture.ssh_directory(),
        )
        .unwrap();
        let directory_index = prepared
            .actions
            .iter()
            .position(|action| action.name().as_str() == "ssh.directory")
            .unwrap();
        let mut first_step = vec![prepared.actions.remove(directory_index)];
        let mut metadata = crate::setup::receipt::ReceiptMetadataSource::system();
        crate::setup::action::apply_plan_with_journal(
            &mut first_step,
            &fixture.receipt_store(),
            &mut metadata,
        )
        .unwrap();
        assert!(fixture.ssh_directory().is_dir());
        assert!(!fixture.ssh_directory().join("authorized_keys").exists());

        prepare_rootless_setup_for_test_with_ssh_directory(
            fixture.effective_with_authorized_key(),
            fixture.context(),
            fixture.layout.clone(),
            fixture.receipt_store(),
            fixture.manifest_store(),
            fixture.ssh_directory(),
        )
        .and_then(apply_rootless_setup)
        .unwrap();
        assert_eq!(
            fs::read_to_string(fixture.ssh_directory().join("authorized_keys")).unwrap(),
            format!("{VALID_CONTROLLER_KEY}\n")
        );
    }

    #[test]
    fn execution_and_publication_failures_preserve_only_safe_bounded_context() {
        let action_id = crate::setup::action::ActionName::parse("identity.directory.root").unwrap();
        let execution = super::map_apply_error(crate::setup::action::ApplyPlanError::Action(
            crate::setup::action::ActionError::apply_failed(action_id),
        ));
        let execution_details = execution.details().unwrap();
        assert_eq!(execution.error_code(), "setup.apply_failed");
        assert_eq!(execution_details["phase"], "execution");
        assert_eq!(execution_details["action_id"], "identity.directory.root");
        assert_eq!(execution_details["cause_category"], "action_apply");
        assert!(execution.to_string().contains("identity.directory.root"));
        assert!(execution.to_string().contains("retry setup"));

        let publication =
            super::map_publication_error(crate::setup::pending::PendingError::DuplicateId);
        let publication_details = publication.details().unwrap();
        assert_eq!(publication.error_code(), "setup.plan_invalid");
        assert_eq!(publication_details["phase"], "publication");
        assert_eq!(publication_details["action_id"], "manifest.publish");
        assert_eq!(publication_details["cause_category"], "pending_projection");
        assert!(publication.to_string().contains("retry setup"));
    }

    #[test]
    fn rootless_setup_preflight_builds_one_closed_directory_then_capability_plan() {
        let fixture = Fixture::new("plan");
        let _snapshots = SnapshotGuard::absent();

        let prepared = fixture
            .prepare(fixture.effective(Some("rootless-worker")))
            .unwrap();
        let nodes = fixture.layout.materialization_nodes();
        let items = prepared.plan_items();

        assert_eq!(items.len(), nodes.len() + 5);
        assert_eq!(
            items[..nodes.len()]
                .iter()
                .map(|item| item.action_id())
                .collect::<Vec<_>>(),
            nodes
                .iter()
                .map(|node| node.action_id())
                .collect::<Vec<_>>()
        );
        assert!(items[..nodes.len()].iter().all(|item| {
            item.component() == "directories"
                && item.operation() == "create"
                && item.privilege() == "none"
                && item.security_caveat() == CAVEAT
        }));
        assert_eq!(
            items[nodes.len()..]
                .iter()
                .map(|item| item.component())
                .collect::<Vec<_>>(),
            ["ssh-server", "tailscale", "git", "styrnd", "sleep-policy"]
        );
        assert!(items[nodes.len()..]
            .iter()
            .all(|item| item.operation() == "needs_human"));
        assert!(!fixture.layout.root().exists());
        assert!(!fixture.receipt_path().exists());
        assert!(!fixture.manifest_path().exists());
    }

    #[test]
    fn rootless_setup_apply_creates_exact_tree_receipt_and_bound_manifest_through_completed_token()
    {
        let fixture = Fixture::new("apply");
        let _snapshots = SnapshotGuard::absent();

        let outcome =
            apply_rootless_setup(fixture.prepare(fixture.effective(None)).unwrap()).unwrap();

        for node in fixture.layout.materialization_nodes() {
            assert!(fixture.layout.path_for_node(node).unwrap().is_dir());
        }
        let receipt = fixture.receipt_store().read_snapshot().unwrap();
        assert_eq!(
            receipt.entry_count(),
            fixture.layout.materialization_nodes().len() + 5
        );
        let manifest = fixture.manifest_store().read().unwrap().manifest;
        assert_eq!(manifest.machine_id, outcome.machine_id());
        assert_eq!(manifest.paths.root, fixture.layout.root().to_str().unwrap());
        assert_eq!(
            manifest.worker_identity.unwrap().name,
            fixture.principal.name()
        );
        assert_eq!(manifest.pending_actions.unwrap().len(), 5);
        assert_eq!(outcome.manifest_path(), fixture.manifest_path());
        assert_eq!(outcome.receipt_path(), fixture.receipt_path());
        assert_eq!(outcome.security_caveat(), CAVEAT);
    }

    #[test]
    fn rootless_setup_healthy_adoption_adds_no_ownership_receipt_entry() {
        let fixture = Fixture::new("adoption");
        let _snapshots = SnapshotGuard::healthy();

        let outcome =
            apply_rootless_setup(fixture.prepare(fixture.effective(None)).unwrap()).unwrap();
        let receipt = fixture.receipt_store().read_snapshot().unwrap();

        assert_eq!(
            receipt.entry_count(),
            fixture.layout.materialization_nodes().len()
        );
        assert!(outcome.pending().is_empty());
        assert!(
            outcome.results()[fixture.layout.materialization_nodes().len()..]
                .iter()
                .all(|result| result.status() == ActionExecutionStatus::Unchanged)
        );
        let bytes = receipt.to_json().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("baseline."));
        let tailscale = fixture
            .manifest_store()
            .read()
            .unwrap()
            .manifest
            .tailscale
            .unwrap();
        assert_eq!(tailscale.mode, Some(manifest::TailscaleMode::Tailscaled));
        assert_eq!(tailscale.unattended, Some(true));
    }

    #[test]
    fn windows_service_without_unattended_stays_pending_and_manifested_false() {
        let fixture = Fixture::new("windows-unattended-false");
        let _snapshots = SnapshotGuard::windows_service_without_unattended();

        let outcome =
            apply_rootless_setup(fixture.prepare(fixture.effective(None)).unwrap()).unwrap();
        assert_eq!(outcome.pending().len(), 1);
        assert_eq!(
            outcome.pending()[0].action_id(),
            "baseline.tailscale.pending"
        );
        let manifest = fixture.manifest_store().read().unwrap().manifest;
        assert_eq!(
            manifest.capabilities.unwrap().get("tailscale"),
            Some(&false)
        );
        let tailscale = manifest.tailscale.unwrap();
        assert_eq!(tailscale.mode, Some(manifest::TailscaleMode::Service));
        assert_eq!(tailscale.unattended, Some(false));
    }

    #[test]
    fn rootless_setup_preserves_machine_id_resource_policy_and_herdr_enabled_on_rerun() {
        let fixture = Fixture::new("preserve");
        let _snapshots = SnapshotGuard::healthy();
        let first =
            apply_rootless_setup(fixture.prepare(fixture.effective(None)).unwrap()).unwrap();
        let first_id = first.machine_id();
        let store = fixture.manifest_store();
        let mut draft = store.read().unwrap().manifest.without_machine_id();
        draft.resources.as_mut().unwrap().policy = Some(manifest::ResourcePolicy {
            reserved_memory_bytes: Some(7_340_032_001),
            reserved_disk_bytes: None,
            reserved_disk_percent: Some(23),
            reserved_cpus: Some(2),
            max_parallel_compile_jobs: Some(5),
            max_parallel_test_jobs: Some(4),
            max_heavy_jobs: Some(1),
            max_job_disk_bytes: Some(9_876_543_210),
        });
        draft.herdr = Some(manifest::Herdr {
            installed: Some(true),
            enabled: Some(false),
            session: Some("fleet".to_owned()),
            autostart: Some("on-demand".to_owned()),
        });
        assert_eq!(store.write_generated(&draft).unwrap(), first_id);

        let second =
            apply_rootless_setup(fixture.prepare(fixture.effective(None)).unwrap()).unwrap();
        let manifest = fixture.manifest_store().read().unwrap().manifest;
        let policy = manifest.resources.unwrap().policy.unwrap();

        assert_eq!(second.machine_id(), first_id);
        assert_eq!(policy.reserved_memory_bytes, Some(7_340_032_001));
        assert_eq!(policy.reserved_disk_percent, Some(23));
        assert_eq!(policy.max_job_disk_bytes, Some(9_876_543_210));
        assert_eq!(manifest.herdr.unwrap().enabled, Some(false));
    }

    #[test]
    fn rootless_setup_rerun_is_byte_identical_and_reports_unchanged_once_per_action() {
        let fixture = Fixture::new("rerun");
        let _snapshots = SnapshotGuard::healthy();
        apply_rootless_setup(fixture.prepare(fixture.effective(None)).unwrap()).unwrap();
        let manifest_before = fs::read(fixture.manifest_path()).unwrap();

        let rerun =
            apply_rootless_setup(fixture.prepare(fixture.effective(None)).unwrap()).unwrap();

        assert_eq!(fs::read(fixture.manifest_path()).unwrap(), manifest_before);
        assert!(rerun
            .results()
            .iter()
            .all(|result| result.status() == ActionExecutionStatus::Unchanged));
        let ids = rerun
            .results()
            .iter()
            .map(|result| result.action_id())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), rerun.plan_items().len());
        assert_eq!(ids.len(), rerun.results().len());
    }

    #[test]
    fn rootless_setup_calls_zero_account_authorization_elevation_or_machine_mutators() {
        let fixture = Fixture::new("rootless-authority");
        let _snapshots = SnapshotGuard::absent();
        let prepared = fixture.prepare(fixture.effective(None)).unwrap();

        assert!(prepared
            .actions
            .iter()
            .all(|action| action.privilege() == Privilege::None));
        assert!(prepared.actions.iter().all(|action| matches!(
            action.parameters(),
            ActionParameters::WorkerDirectory(_) | ActionParameters::Foundation(_)
        )));
        apply_rootless_setup(prepared).unwrap();
        let receipt: serde_json::Value = serde_json::from_slice(
            &fixture
                .receipt_store()
                .read_snapshot()
                .unwrap()
                .to_json()
                .unwrap(),
        )
        .unwrap();
        for entry in receipt["entries"].as_array().unwrap() {
            for field in [
                "files_created",
                "files_modified",
                "services",
                "accounts",
                "registry_keys",
                "firewall_rules",
            ] {
                assert_eq!(entry[field], serde_json::json!([]));
            }
            assert!(entry["download_provenance"].is_null());
        }
    }

    #[test]
    fn rootless_setup_invalid_existing_manifest_or_receipt_fails_before_directory_mutation() {
        for invalid_manifest in [true, false] {
            let fixture = Fixture::new(if invalid_manifest {
                "bad-manifest"
            } else {
                "bad-receipt"
            });
            let _snapshots = SnapshotGuard::absent();
            if invalid_manifest {
                fixture.harden_user_file(&fixture.manifest_path(), b"not = [valid\n");
            } else {
                fixture.harden_user_file(&fixture.receipt_path(), b"{}\n");
            }

            let error = fixture.prepare(fixture.effective(None)).unwrap_err();

            assert_eq!(error.exit_code(), 13);
            assert_eq!(
                error.error_code(),
                if invalid_manifest {
                    "setup.plan_invalid"
                } else {
                    "setup.receipt_conflict"
                }
            );
            assert!(!fixture.layout.root().exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn rootless_setup_apply_failure_leaves_exact_receipt_prefix_and_no_new_manifest_then_recovers()
    {
        let fixture = Fixture::new("apply-failure");
        let _snapshots = SnapshotGuard::absent();
        let prepared = fixture.prepare(fixture.effective(None)).unwrap();
        platform::set_worker_node_post_publish_failure_for_action_test(true);

        let error = apply_rootless_setup(prepared).unwrap_err();
        platform::set_worker_node_post_publish_failure_for_action_test(false);

        assert_eq!(error.error_code(), "setup.apply_failed");
        assert_eq!(
            fixture
                .receipt_store()
                .read_snapshot()
                .unwrap()
                .entry_count(),
            1
        );
        assert!(!fixture.manifest_path().exists());

        apply_rootless_setup(fixture.prepare(fixture.effective(None)).unwrap()).unwrap();
        assert_eq!(
            fixture
                .receipt_store()
                .read_snapshot()
                .unwrap()
                .entry_count(),
            fixture.layout.materialization_nodes().len() + 5
        );
        assert!(fixture.manifest_path().exists());
    }

    #[test]
    fn rootless_setup_publication_failure_retains_old_manifest_receipt_and_intent_then_recovers() {
        let fixture = Fixture::new("publication-failure");
        {
            let _snapshots = SnapshotGuard::healthy();
            apply_rootless_setup(fixture.prepare(fixture.effective(Some("before"))).unwrap())
                .unwrap();
        }
        let _snapshots = SnapshotGuard::absent();
        let manifest_before = fs::read(fixture.manifest_path()).unwrap();
        let receipt_before = fixture
            .receipt_store()
            .read_snapshot()
            .unwrap()
            .to_json()
            .unwrap();
        let failing_manifest =
            manifest::MachineManifestStore::new_user_with_worker_layout_failing_publication_for_test(
                fixture.manifest_path(),
                fixture.principal.clone(),
                &fixture.layout,
            )
            .unwrap();
        let prepared = prepare_rootless_setup_for_test(
            fixture.effective(Some("after")),
            fixture.context(),
            fixture.layout.clone(),
            fixture.receipt_store(),
            failing_manifest,
        )
        .unwrap();

        let error = apply_rootless_setup(prepared).unwrap_err();

        assert_eq!(error.error_code(), "setup.apply_failed");
        assert_eq!(fs::read(fixture.manifest_path()).unwrap(), manifest_before);
        fixture.receipt_store().read_snapshot().unwrap();
        assert!(fixture.pending_intent_path().exists());
        assert_ne!(fs::read(fixture.receipt_path()).unwrap(), receipt_before);

        apply_rootless_setup(fixture.prepare(fixture.effective(Some("after"))).unwrap()).unwrap();
        assert_eq!(
            fixture.manifest_store().read().unwrap().manifest.name,
            "after"
        );
        assert!(!fixture.pending_intent_path().exists());
    }

    #[test]
    fn rootless_setup_concurrent_callers_converge_to_one_uuid_prefix_and_manifest() {
        let fixture = Fixture::new("concurrent");
        let _snapshots = SnapshotGuard::healthy();
        let first = fixture.prepare(fixture.effective(None)).unwrap();
        let second = fixture.prepare(fixture.effective(None)).unwrap();

        let first = std::thread::spawn(|| apply_rootless_setup(first));
        let second = std::thread::spawn(|| apply_rootless_setup(second));
        let first = first.join().unwrap().unwrap();
        let second = second.join().unwrap().unwrap();

        assert_eq!(first.machine_id(), second.machine_id());
        assert_eq!(
            fixture
                .receipt_store()
                .read_snapshot()
                .unwrap()
                .entry_count(),
            fixture.layout.materialization_nodes().len()
        );
        let stored = fixture.manifest_store().read().unwrap().manifest;
        assert_eq!(stored.machine_id, first.machine_id());
        assert_eq!(
            fs::read_to_string(fixture.manifest_path()).unwrap(),
            stored.to_toml().unwrap()
        );
    }

    #[test]
    fn rootless_setup_pending_policy_failure_occurs_only_after_correct_durable_publication() {
        let fixture = Fixture::new("strict-pending");
        let _snapshots = SnapshotGuard::absent();

        let error =
            apply_rootless_setup(fixture.prepare(fixture.strict_effective()).unwrap()).unwrap_err();

        assert_eq!(error.error_code(), "setup.needs_human");
        assert_eq!(error.exit_code(), 13);
        let outcome = error.outcome().unwrap();
        assert_eq!(outcome.pending().len(), 5);
        assert!(fixture.manifest_path().exists());
        assert!(fixture.receipt_path().exists());
        assert!(!fixture.pending_intent_path().exists());
        assert_eq!(
            fixture
                .manifest_store()
                .read()
                .unwrap()
                .manifest
                .pending_actions
                .unwrap()
                .len(),
            5
        );
    }
}
