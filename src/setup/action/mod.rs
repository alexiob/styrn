//! Typed, idempotent setup action boundary.
//!
//! An [`Action`] is the sole normal mutation path for setup. Its public
//! `apply` method always checks first; the mutation hook is deliberately
//! confined to this module so callers cannot bypass that gate.

#![allow(unexpected_cfgs)] // Exact rustc compile-boundary fixtures use private cfg names.

#[cfg(not(action_core_fixture))]
pub(crate) use crate::platform::WorkerDirectoryNode;
use std::fmt;
use std::marker::PhantomData;
#[cfg(not(action_core_fixture))]
use std::path::PathBuf;
use thiserror::Error;

/// Unforgeable authority required by receipt mutation sessions. Its field is
/// private to this module, so read-only plan descendants cannot mint one.
pub(crate) struct JournalAuthority(());

#[cfg(test)]
impl JournalAuthority {
    pub(in crate::setup) const fn for_test() -> Self {
        Self(())
    }
}

/// Unforgeable authority required by native setup mutation.
///
/// Production construction remains inside this closed action module. Tests use
/// the platform-owned test token so source-including platform fixtures remain
/// independent of the setup module graph.
#[cfg(not(test))]
#[allow(dead_code)] // Constructed by the T0.14 per-node execution gate.
pub(crate) struct NativeMutationAuthority(());

#[cfg(test)]
pub(crate) type NativeMutationAuthority = crate::platform::TestNativeMutationAuthority;

pub(in crate::setup::action) fn native_mutation_authority() -> NativeMutationAuthority {
    #[cfg(not(test))]
    {
        NativeMutationAuthority(())
    }
    #[cfg(test)]
    {
        crate::platform::TestNativeMutationAuthority::for_test()
    }
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

/// The finalized, typed description of one successful action mutation.
///
/// Fields are private and construction stays behind the action mutation gate;
/// receipt publication may inspect them but plan/dry-run code cannot forge one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ActionEffect {
    directories_created: Vec<CreatedDirectoryEffect>,
    files_created: Vec<CreatedFileEffect>,
    files_modified: Vec<ModifiedFileEffect>,
    services: Vec<String>,
    accounts: Vec<String>,
    registry_keys: Vec<String>,
    firewall_rules: Vec<String>,
    download_provenance: Option<DownloadProvenanceEffect>,
}

/// A finalized action effect whose lifetime is bounded by the native mutation
/// authority that verified it. The wrapper cannot be cloned, copied, or
/// serialized, so callers can only consume the borrowed effect inside the
/// durable receipt callback.
pub(crate) struct VerifiedActionEffect<'authority> {
    effect: &'authority ActionEffect,
    _authority: PhantomData<&'authority mut ()>,
}

impl VerifiedActionEffect<'_> {
    pub(in crate::setup) fn effect(&self) -> &ActionEffect {
        self.effect
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MutationCompletion {
    Applied,
    AppliedThenFailed(ActionError),
    AppliedThenFailedRetainingSucceededIntent(ActionError),
}

#[derive(Debug)]
pub(crate) enum PreparedExecutionError<BindingError> {
    Action(ActionError),
    ReceiptConflict,
    Binding(BindingError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CreatedDirectoryEffect {
    path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CreatedFileEffect {
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ModifiedFileEffect {
    path: String,
    before_sha256: String,
    backup_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DownloadProvenanceEffect {
    url: String,
    version: String,
    sha256: String,
}

impl ActionEffect {
    pub(in crate::setup) fn directories_created(&self) -> &[CreatedDirectoryEffect] {
        &self.directories_created
    }

    pub(in crate::setup) fn files_created(&self) -> &[CreatedFileEffect] {
        &self.files_created
    }

    pub(in crate::setup) fn files_modified(&self) -> &[ModifiedFileEffect] {
        &self.files_modified
    }

    pub(in crate::setup) fn services(&self) -> &[String] {
        &self.services
    }

    pub(in crate::setup) fn accounts(&self) -> &[String] {
        &self.accounts
    }

    pub(in crate::setup) fn registry_keys(&self) -> &[String] {
        &self.registry_keys
    }

    pub(in crate::setup) fn firewall_rules(&self) -> &[String] {
        &self.firewall_rules
    }

    pub(in crate::setup) fn download_provenance(&self) -> Option<&DownloadProvenanceEffect> {
        self.download_provenance.as_ref()
    }

    #[cfg(test)]
    fn test_fixture(marker: u8) -> Self {
        #[cfg(not(target_os = "windows"))]
        let (created_path, modified_path, backup_path) = (
            format!("/opt/styrn/test/{marker}"),
            format!("/etc/styrn/test/{marker}.toml"),
            format!("/var/lib/styrn/backups/{marker}.toml"),
        );
        #[cfg(target_os = "windows")]
        let (created_path, modified_path, backup_path) = (
            format!(r"C:\ProgramData\Styrn\test\{marker}"),
            format!(r"C:\ProgramData\Styrn\test\{marker}.toml"),
            format!(r"C:\ProgramData\Styrn\backups\{marker}.toml"),
        );
        Self {
            directories_created: Vec::new(),
            files_created: vec![CreatedFileEffect {
                path: created_path,
                sha256: format!("{marker:064}"),
            }],
            files_modified: vec![ModifiedFileEffect {
                path: modified_path,
                before_sha256: "a".repeat(64),
                backup_path,
            }],
            services: vec![format!("styrn-test-{marker}")],
            accounts: vec![format!("styrn-test-{marker}")],
            registry_keys: vec![format!(r"HKLM\Software\Styrn\Test{marker}")],
            firewall_rules: vec![format!("Styrn Test {marker}")],
            download_provenance: Some(DownloadProvenanceEffect {
                url: format!("https://downloads.example.test/test/{marker}"),
                version: format!("1.0.{marker}"),
                sha256: "b".repeat(64),
            }),
        }
    }
}

impl CreatedDirectoryEffect {
    pub(in crate::setup) fn path(&self) -> &str {
        &self.path
    }
}

impl CreatedFileEffect {
    pub(in crate::setup) fn path(&self) -> &str {
        &self.path
    }

    pub(in crate::setup) fn sha256(&self) -> &str {
        &self.sha256
    }
}

impl ModifiedFileEffect {
    pub(in crate::setup) fn path(&self) -> &str {
        &self.path
    }

    pub(in crate::setup) fn before_sha256(&self) -> &str {
        &self.before_sha256
    }

    pub(in crate::setup) fn backup_path(&self) -> &str {
        &self.backup_path
    }
}

impl DownloadProvenanceEffect {
    pub(in crate::setup) fn url(&self) -> &str {
        &self.url
    }

    pub(in crate::setup) fn version(&self) -> &str {
        &self.version
    }

    pub(in crate::setup) fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[cfg(test)]
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
#[cfg(test)]
use std::{fs, path::Path};

#[cfg(test)]
#[derive(Clone)]
pub(super) struct TestMetrics {
    check_calls: Arc<AtomicUsize>,
    prepare_calls: Arc<AtomicUsize>,
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

    pub(super) fn prepare_calls(&self) -> usize {
        self.prepare_calls.load(Ordering::SeqCst)
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
    severity: PendingSeverity,
    instructions: HumanInstructions,
    fragment: Option<ScriptFragment>,
}

impl NeedsHuman {
    pub(in crate::setup::action) fn new(
        instructions: HumanInstructions,
        fragment: Option<ScriptFragment>,
    ) -> Self {
        Self {
            severity: PendingSeverity::Warning,
            instructions,
            fragment,
        }
    }

    pub(in crate::setup::action) fn with_severity(mut self, severity: PendingSeverity) -> Self {
        self.severity = severity;
        self
    }

    pub(crate) fn severity(&self) -> PendingSeverity {
        self.severity
    }

    pub(crate) fn instructions(&self) -> &HumanInstructions {
        &self.instructions
    }

    pub(crate) fn fragment(&self) -> Option<&ScriptFragment> {
        self.fragment.as_ref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PendingSeverity {
    Info,
    Warning,
    Error,
}

/// One current unresolved action, preserving its stable plan identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingAction {
    parameters: ActionParameters,
    needs_human: NeedsHuman,
}

impl PendingAction {
    fn new(id: ActionName, needs_human: NeedsHuman) -> Self {
        Self {
            parameters: ActionParameters::Foundation(id),
            needs_human,
        }
    }

    fn from_action(action: &Action, needs_human: NeedsHuman) -> Self {
        Self {
            parameters: action.parameters(),
            needs_human,
        }
    }

    pub(crate) fn id(&self) -> &ActionName {
        self.parameters.action_id()
    }

    pub(in crate::setup) fn parameters(&self) -> &ActionParameters {
        &self.parameters
    }

    pub(crate) fn severity(&self) -> PendingSeverity {
        self.needs_human.severity()
    }

    pub(crate) fn needs_human(&self) -> &NeedsHuman {
        &self.needs_human
    }

    pub(crate) fn fragment_action_id(&self) -> Option<&str> {
        match self.needs_human.fragment() {
            Some(ScriptFragment::DeferredAction(action)) => Some(action.as_str()),
            None => None,
        }
    }
}

/// Closed, typed receipt parameters retained before any action mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ActionParameters {
    Foundation(ActionName),
    #[cfg(not(action_core_fixture))]
    WorkerDirectory(WorkerDirectoryActionParameters),
}

impl ActionParameters {
    pub(in crate::setup) fn action_id(&self) -> &ActionName {
        match self {
            Self::Foundation(action_id) => action_id,
            #[cfg(not(action_core_fixture))]
            Self::WorkerDirectory(parameters) => parameters.action_id(),
        }
    }
}

#[cfg(not(action_core_fixture))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WorkerDirectoryActionParameters {
    action_id: ActionName,
    installation_scope: crate::platform::InstallationScope,
    principal: crate::platform::WorkerPrincipal,
    root: PathBuf,
    node: WorkerDirectoryNode,
    path: PathBuf,
}

#[cfg(not(action_core_fixture))]
impl WorkerDirectoryActionParameters {
    pub(in crate::setup) fn action_id(&self) -> &ActionName {
        &self.action_id
    }

    pub(in crate::setup) fn installation_scope(&self) -> crate::platform::InstallationScope {
        self.installation_scope
    }

    pub(in crate::setup) fn principal(&self) -> &crate::platform::WorkerPrincipal {
        &self.principal
    }

    pub(in crate::setup) fn root(&self) -> &std::path::Path {
        &self.root
    }

    pub(in crate::setup) fn node(&self) -> WorkerDirectoryNode {
        self.node
    }

    pub(in crate::setup) fn path(&self) -> &std::path::Path {
        &self.path
    }
}

/// One exact closed action plus its expected effect, retained durably before
/// mutation and compared structurally during prepared-intent recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedAction {
    parameters: ActionParameters,
    effect: ActionEffect,
}

impl PreparedAction {
    pub(in crate::setup) fn parameters(&self) -> &ActionParameters {
        &self.parameters
    }

    pub(in crate::setup) fn effect(&self) -> &ActionEffect {
        &self.effect
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

    pub(in crate::setup) fn apply_failed(action: ActionName) -> Self {
        Self::ApplyFailed { action }
    }
}

/// The closed setup action plan type. Future component actions extend this
/// enum; there is no open implementation trait or raw mutation entry point.
pub(crate) enum Action {
    Foundation(FoundationAction),
    #[cfg(not(action_core_fixture))]
    WorkerDirectory(Box<worker_directory::WorkerDirectoryAction>),
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
    marker: u8,
    effect: Box<ActionEffect>,
    parameters: ActionParameters,
}

#[cfg(test)]
#[derive(Clone)]
enum TestBehavior {
    StateDriven,
    DynamicFile {
        path: std::path::PathBuf,
        replacement: Vec<u8>,
    },
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
                    severity: PendingSeverity::Warning,
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
            Self::test_action("test.state", 1, privilege, state, TestBehavior::StateDriven)
        }

        #[cfg(test)]
        pub(super) fn test_journaled_state(
            name: &str,
            marker: u8,
            privilege: Privilege,
            state: Arc<Mutex<Vec<u8>>>,
        ) -> (Self, TestMetrics) {
            Self::test_action(name, marker, privilege, state, TestBehavior::StateDriven)
        }

        #[cfg(test)]
        pub(super) fn test_journaled_failure(
            name: &str,
            marker: u8,
            privilege: Privilege,
            state: Arc<Mutex<Vec<u8>>>,
        ) -> (Self, TestMetrics) {
            Self::test_action(name, marker, privilege, state, TestBehavior::ApplyFailure)
        }

        #[cfg(test)]
        pub(super) fn test_journaled_with_effect(
            name: &str,
            marker: u8,
            privilege: Privilege,
            state: Arc<Mutex<Vec<u8>>>,
            effect: ActionEffect,
        ) -> (Self, TestMetrics) {
            let (mut wrapped, metrics) =
                Self::test_action(name, marker, privilege, state, TestBehavior::StateDriven);
            let Self::Test(action) = &mut wrapped else {
                unreachable!("test action constructor must return the test variant")
            };
            *action.effect = effect;
            (wrapped, metrics)
        }

        #[cfg(test)]
        pub(super) fn test_dynamic_file_modification(
            name: &str,
            path: std::path::PathBuf,
        ) -> (Self, TestMetrics) {
            Self::test_action(
                name,
                1,
                Privilege::None,
                Arc::new(Mutex::new(Vec::new())),
                TestBehavior::DynamicFile {
                    path,
                    replacement: b"after-state\n".to_vec(),
                },
            )
        }

        #[cfg(test)]
        pub(super) fn test_needs_human(
            privilege: Privilege,
            state: Arc<Mutex<Vec<u8>>>,
            needs_human: NeedsHuman,
        ) -> (Self, TestMetrics) {
            Self::test_named_needs_human("test.state", privilege, state, needs_human)
        }

        #[cfg(test)]
        pub(super) fn test_named_needs_human(
            name: &str,
            privilege: Privilege,
            state: Arc<Mutex<Vec<u8>>>,
            needs_human: NeedsHuman,
        ) -> (Self, TestMetrics) {
            Self::test_action(
                name,
                1,
                privilege,
                state,
                TestBehavior::NeedsHuman(needs_human),
            )
        }

        #[cfg(test)]
        pub(super) fn test_check_failure(
            privilege: Privilege,
            state: Arc<Mutex<Vec<u8>>>,
        ) -> (Self, TestMetrics) {
            Self::test_action(
                "test.state",
                1,
                privilege,
                state,
                TestBehavior::CheckFailure,
            )
        }

        #[cfg(test)]
        pub(super) fn test_apply_failure(
            privilege: Privilege,
            state: Arc<Mutex<Vec<u8>>>,
        ) -> (Self, TestMetrics) {
            Self::test_action(
                "test.state",
                1,
                privilege,
                state,
                TestBehavior::ApplyFailure,
            )
        }

        #[cfg(test)]
        fn test_action(
            name: &str,
            marker: u8,
            privilege: Privilege,
            state: Arc<Mutex<Vec<u8>>>,
            behavior: TestBehavior,
        ) -> (Self, TestMetrics) {
            let metrics = TestMetrics {
                check_calls: Arc::new(AtomicUsize::new(0)),
                prepare_calls: Arc::new(AtomicUsize::new(0)),
                mutation_calls: Arc::new(AtomicUsize::new(0)),
            };
            let action = TestAction {
                name: ActionName::parse(name).expect("test action name must be valid"),
                description: ActionDescription::new("Converge test state")
                    .expect("test description must be valid"),
                privilege,
                state,
                metrics: metrics.clone(),
                behavior,
                marker,
                effect: Box::new(ActionEffect::test_fixture(marker)),
                parameters: ActionParameters::Foundation(
                    ActionName::parse(name).expect("test action name must be valid"),
                ),
            };
            (Self::Test(action), metrics)
        }

        #[cfg(all(test, not(action_core_fixture)))]
        pub(super) fn test_worker_directory(
            installation_scope: crate::platform::InstallationScope,
            principal: crate::platform::WorkerPrincipal,
            root: PathBuf,
            node: WorkerDirectoryNode,
            path: PathBuf,
            state: Arc<Mutex<Vec<u8>>>,
        ) -> (Self, TestMetrics) {
            Self::test_worker_directory_with_behavior(
                installation_scope,
                principal,
                root,
                node,
                path,
                state,
                TestBehavior::StateDriven,
            )
        }

        #[cfg(all(test, not(action_core_fixture)))]
        pub(super) fn test_worker_directory_needs_human(
            installation_scope: crate::platform::InstallationScope,
            principal: crate::platform::WorkerPrincipal,
            root: PathBuf,
            node: WorkerDirectoryNode,
            path: PathBuf,
            state: Arc<Mutex<Vec<u8>>>,
            needs_human: NeedsHuman,
        ) -> (Self, TestMetrics) {
            Self::test_worker_directory_with_behavior(
                installation_scope,
                principal,
                root,
                node,
                path,
                state,
                TestBehavior::NeedsHuman(needs_human),
            )
        }

        #[cfg(all(test, not(action_core_fixture)))]
        fn test_worker_directory_with_behavior(
            installation_scope: crate::platform::InstallationScope,
            principal: crate::platform::WorkerPrincipal,
            root: PathBuf,
            node: WorkerDirectoryNode,
            path: PathBuf,
            state: Arc<Mutex<Vec<u8>>>,
            behavior: TestBehavior,
        ) -> (Self, TestMetrics) {
            let action_id = ActionName::parse(&node.action_id())
                .expect("worker directory action name must be valid");
            let effect_path = path
                .to_str()
                .expect("worker directory receipt test path must be Unicode")
                .to_owned();
            let (mut action, metrics) =
                Self::test_action(action_id.as_str(), 1, Privilege::None, state, behavior);
            let Self::Test(test) = &mut action else {
                unreachable!("test action constructor must return the test variant")
            };
            test.parameters = ActionParameters::WorkerDirectory(WorkerDirectoryActionParameters {
                action_id,
                installation_scope,
                principal,
                root,
                node,
                path,
            });
            *test.effect = ActionEffect {
                directories_created: vec![CreatedDirectoryEffect { path: effect_path }],
                files_created: Vec::new(),
                files_modified: Vec::new(),
                services: Vec::new(),
                accounts: Vec::new(),
                registry_keys: Vec::new(),
                firewall_rules: Vec::new(),
                download_provenance: None,
            };
            (action, metrics)
        }

        pub(crate) fn name(&self) -> &ActionName {
            match self {
                Self::Foundation(action) => &action.name,
                #[cfg(not(action_core_fixture))]
                Self::WorkerDirectory(action) => action.name(),
                #[cfg(test)]
                Self::Test(action) => &action.name,
            }
        }

        pub(in crate::setup::action) fn parameters(&self) -> ActionParameters {
            match self {
                Self::Foundation(action) => ActionParameters::Foundation(action.name.clone()),
                #[cfg(not(action_core_fixture))]
                Self::WorkerDirectory(action) => action.parameters(),
                #[cfg(test)]
                Self::Test(action) => action.parameters.clone(),
            }
        }

        pub(crate) fn check(&self) -> Result<ActionCheck, ActionError> {
            match self {
                Self::Foundation(action) => Ok(action.check.clone()),
                #[cfg(not(action_core_fixture))]
                Self::WorkerDirectory(action) => Ok(action.check()),
                #[cfg(test)]
                Self::Test(action) => {
                    action.metrics.check_calls.fetch_add(1, Ordering::SeqCst);
                    match &action.behavior {
                        TestBehavior::StateDriven | TestBehavior::ApplyFailure => {
                            if action.state.lock().unwrap().contains(&action.marker) {
                                Ok(ActionCheck::Done)
                            } else {
                                Ok(ActionCheck::Todo)
                            }
                        }
                        TestBehavior::DynamicFile { path, replacement } => fs::read(path)
                            .map(|contents| {
                                if contents == *replacement {
                                    ActionCheck::Done
                                } else {
                                    ActionCheck::Todo
                                }
                            })
                            .map_err(|_| ActionError::check_failed(action.name.clone())),
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
                #[cfg(not(action_core_fixture))]
                Self::WorkerDirectory(_) => Privilege::None,
                #[cfg(test)]
                Self::Test(action) => action.privilege,
            }
        }

        pub(crate) fn plan_operation(&self) -> PlanOperation {
            match self {
                Self::Foundation(action) => action.operation,
                #[cfg(not(action_core_fixture))]
                Self::WorkerDirectory(_) => PlanOperation::Create,
                #[cfg(test)]
                Self::Test(_) => PlanOperation::Reconfigure,
            }
        }

        pub(crate) fn describe(&self) -> &ActionDescription {
            match self {
                Self::Foundation(action) => &action.description,
                #[cfg(not(action_core_fixture))]
                Self::WorkerDirectory(action) => action.description(),
                #[cfg(test)]
                Self::Test(action) => &action.description,
            }
        }

        pub(in crate::setup::action) fn apply(&mut self) -> Result<ApplyOutcome, ActionError> {
            #[cfg(not(action_core_fixture))]
            if let Self::WorkerDirectory(action) = self {
                return Err(ActionError::apply_failed(action.name().clone()));
            }
            match self.check()? {
                ActionCheck::Done => Ok(ApplyOutcome::Noop),
                ActionCheck::Todo => execute(self).map(ApplyOutcome::Applied),
                ActionCheck::NeedsHuman(needs_human) => Ok(ApplyOutcome::NeedsHuman(needs_human)),
            }
        }

        pub(in crate::setup::action) fn prepare(&self) -> Result<PreparedAction, ActionError> {
            let effect = match self {
                Self::Foundation(action) => Err(ActionError::apply_failed(action.name.clone())),
                #[cfg(not(action_core_fixture))]
                Self::WorkerDirectory(action) => Ok(action.expected_effect()),
                #[cfg(test)]
                Self::Test(action) => {
                    action.metrics.prepare_calls.fetch_add(1, Ordering::SeqCst);
                    match &action.behavior {
                        TestBehavior::DynamicFile { path, .. } => dynamic_file_effect(path)
                            .ok_or_else(|| ActionError::apply_failed(action.name.clone())),
                        _ => Ok((*action.effect).clone()),
                    }
                }
            }?;
            Ok(PreparedAction {
                parameters: self.parameters(),
                effect,
            })
        }

        pub(in crate::setup::action) fn execute_prepared_and_bind<Value, BindingError>(
            &mut self,
            bind: impl for<'authority> FnOnce(
                VerifiedActionEffect<'authority>,
            ) -> Result<Value, BindingError>,
        ) -> Result<(MutationCompletion, Value), PreparedExecutionError<BindingError>> {
            match self {
                #[cfg(not(action_core_fixture))]
                Self::WorkerDirectory(action) => action.execute_prepared_and_bind(bind),
                _ => {
                    let effect = execute(self).map_err(PreparedExecutionError::Action)?;
                    let value = bind(VerifiedActionEffect {
                        effect: &effect,
                        _authority: PhantomData,
                    })
                    .map_err(PreparedExecutionError::Binding)?;
                    Ok((MutationCompletion::Applied, value))
                }
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
            #[cfg(not(action_core_fixture))]
            Action::WorkerDirectory(action) => {
                Err(ActionError::apply_failed(action.name().clone()))
            }
            #[cfg(test)]
            Action::Test(action) => {
                action.metrics.mutation_calls.fetch_add(1, Ordering::SeqCst);
                if matches!(action.behavior, TestBehavior::ApplyFailure) {
                    return Err(ActionError::apply_failed(action.name.clone()));
                }
                if let TestBehavior::DynamicFile { path, replacement } = &action.behavior {
                    let effect = dynamic_file_effect(path)
                        .ok_or_else(|| ActionError::apply_failed(action.name.clone()))?;
                    let before = fs::read(path)
                        .map_err(|_| ActionError::apply_failed(action.name.clone()))?;
                    fs::write(dynamic_backup_path(path), before)
                        .and_then(|()| fs::write(path, replacement))
                        .map_err(|_| ActionError::apply_failed(action.name.clone()))?;
                    return Ok(effect);
                }
                action.state.lock().unwrap().push(action.marker);
                Ok((*action.effect).clone())
            }
        }
    }

    #[cfg(test)]
    fn dynamic_file_effect(path: &Path) -> Option<ActionEffect> {
        let contents = fs::read(path).ok()?;
        let before_sha256 = match contents.as_slice() {
            b"before-state\n" => "b40af702b6375903b1e09c6c851d1828ac225b5356aef2c1c60e308efaf89944",
            b"after-state\n" => "e540ab86e563981f2e832b9162298afa4877a49f2eea547eb59bda35008e4f80",
            _ => return None,
        };
        Some(ActionEffect {
            directories_created: Vec::new(),
            files_created: Vec::new(),
            files_modified: vec![ModifiedFileEffect {
                path: path.to_string_lossy().into_owned(),
                before_sha256: before_sha256.to_owned(),
                backup_path: dynamic_backup_path(path).to_string_lossy().into_owned(),
            }],
            services: Vec::new(),
            accounts: Vec::new(),
            registry_keys: Vec::new(),
            firewall_rules: Vec::new(),
            download_provenance: None,
        })
    }

    #[cfg(test)]
    fn dynamic_backup_path(path: &Path) -> std::path::PathBuf {
        path.with_extension("styrn-backup")
    }
}

#[cfg(not(action_core_fixture))]
mod worker_directory;
#[cfg(not(action_core_fixture))]
#[allow(unused_imports)] // T0.20 consumes the production constructor.
pub(in crate::setup) use worker_directory::current_user_worker_directory_plan;
#[cfg(test)]
pub(in crate::setup::action) use worker_directory::current_user_worker_directory_plan_for_test;
#[cfg(not(action_core_fixture))]
mod authorization;
#[cfg(not(action_core_fixture))]
mod execution;
#[cfg(not(action_core_fixture))]
#[allow(unused_imports)] // Private canonical route; T0.20 adds its authorized frontend.
use execution::apply_plan_with_journal;
#[cfg(not(action_core_fixture))]
#[allow(unused_imports)] // Opaque completion capability consumed by setup projections.
pub(in crate::setup) use execution::CompletedExecutionToken;

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
