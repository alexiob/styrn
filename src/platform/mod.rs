#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;

use std::path::Path;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InstallationScope {
    User,
    System,
}

impl std::str::FromStr for InstallationScope {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "user" => Ok(Self::User),
            "system" => Ok(Self::System),
            _ => Err("scope must be 'user' or 'system'"),
        }
    }
}

/// The scope-selected worker filesystem root and its complete fixed layout.
///
/// Keeping construction private ensures later setup actions cannot add an
/// undeclared directory or accidentally treat an override as a parent prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)] // Consumed by the T0.14 setup action integration follow-up.
pub(crate) struct WorkerDirectoryLayout {
    scope: InstallationScope,
    root: PathBuf,
    repos: PathBuf,
    jobs: PathBuf,
    cache: PathBuf,
    artifacts: PathBuf,
    logs: PathBuf,
    creation_policy: WorkerRootCreationPolicy,
    principal: WorkerPrincipal,
    #[cfg(test)]
    principal_revalidation: Option<WorkerPrincipalRevalidationTest>,
}

/// Closed identity for one node in the native worker-directory layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkerDirectoryNode {
    Support { ordinal: u16 },
    Root,
    Repos,
    Jobs,
    Cache,
    Artifacts,
    Logs,
}

impl WorkerDirectoryNode {
    #[allow(dead_code)] // Consumed by the T0.14 production Action integration.
    pub(crate) fn action_id(self) -> String {
        match self {
            Self::Support { ordinal } => format!("identity.directory.support-{ordinal}"),
            Self::Root => "identity.directory.root".to_owned(),
            Self::Repos => "identity.directory.repos".to_owned(),
            Self::Jobs => "identity.directory.jobs".to_owned(),
            Self::Cache => "identity.directory.cache".to_owned(),
            Self::Artifacts => "identity.directory.artifacts".to_owned(),
            Self::Logs => "identity.directory.logs".to_owned(),
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
enum WorkerPrincipalRevalidationTest {
    Resolved {
        principal: WorkerPrincipal,
        current: Option<WorkerPrincipal>,
    },
    Deleted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum WorkerRootCreationPolicy {
    ExistingParent { allow_untrusted_parent_create: bool },
    CreateMissingFrom(PathBuf),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkerDirectoryNodeDisposition {
    Created,
    Existing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkerDirectoryIdentity {
    volume: u64,
    file_id: [u8; 16],
}

impl WorkerDirectoryIdentity {
    #[cfg(unix)]
    pub(super) fn from_unix(device: u64, inode: u64) -> Self {
        let mut file_id = [0_u8; 16];
        file_id[..8].copy_from_slice(&inode.to_ne_bytes());
        Self {
            volume: device,
            file_id,
        }
    }

    #[cfg(target_os = "windows")]
    pub(super) fn from_windows(volume: u64, file_id: [u8; 16]) -> Self {
        Self { volume, file_id }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct WorkerDirectoryNodeObservation {
    path: PathBuf,
    disposition: WorkerDirectoryNodeDisposition,
    identity: WorkerDirectoryIdentity,
}

#[allow(dead_code)] // Consumed by the deferred T0.14 receipt integration.
impl WorkerDirectoryNodeObservation {
    pub(in crate::platform) fn new(
        path: PathBuf,
        disposition: WorkerDirectoryNodeDisposition,
        identity: WorkerDirectoryIdentity,
    ) -> Self {
        Self {
            path,
            disposition,
            identity,
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn disposition(&self) -> WorkerDirectoryNodeDisposition {
        self.disposition
    }

    pub(crate) fn identity(&self) -> WorkerDirectoryIdentity {
        self.identity
    }
}

pub(crate) struct WorkerDirectoryCreation {
    nodes: [WorkerDirectoryNodeObservation; 6],
    lease: platform_impl::WorkerDirectoryLease,
}

pub(crate) struct WorkerDirectoryCreationError {
    inner: Box<WorkerDirectoryCreationErrorInner>,
}

enum WorkerDirectoryCreationErrorInner {
    Native(std::io::Error),
    #[cfg(target_os = "windows")]
    RetainedWindowsEvidence {
        primary: std::io::Error,
        operation_error: Option<std::io::Error>,
        privilege_cleanup_failed: bool,
        evidence: platform_impl::WorkerDirectoryFailureEvidence,
    },
}

#[cfg(target_os = "windows")]
#[allow(dead_code)] // Consumed by the deferred T0.14 receipt binding integration.
pub(crate) struct VerifiedWorkerDirectoryFailureBinding<'authority> {
    nodes: &'authority [WorkerDirectoryNodeObservation],
    _authority: &'authority platform_impl::WorkerDirectoryFailureEvidence,
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
#[allow(dead_code)] // Consumed by the deferred T0.14 receipt binding integration.
pub(crate) enum WorkerDirectoryFailureBindingError<BindingError> {
    NoRetainedEvidence,
    Reverification(std::io::Error),
    Binding(BindingError),
}

#[allow(dead_code)] // Detailed evidence access is consumed by the deferred T0.14 receipt integration.
impl WorkerDirectoryCreationError {
    fn native(error: std::io::Error) -> Self {
        Self {
            inner: Box::new(WorkerDirectoryCreationErrorInner::Native(error)),
        }
    }

    #[cfg(target_os = "windows")]
    pub(in crate::platform) fn with_windows_retained_evidence(
        primary: std::io::Error,
        operation_error: Option<std::io::Error>,
        privilege_cleanup_failed: bool,
        evidence: platform_impl::WorkerDirectoryFailureEvidence,
    ) -> Self {
        Self {
            inner: Box::new(WorkerDirectoryCreationErrorInner::RetainedWindowsEvidence {
                primary,
                operation_error,
                privilege_cleanup_failed,
                evidence,
            }),
        }
    }

    pub(crate) fn kind(&self) -> std::io::ErrorKind {
        match self.inner.as_ref() {
            WorkerDirectoryCreationErrorInner::Native(error) => error.kind(),
            #[cfg(target_os = "windows")]
            WorkerDirectoryCreationErrorInner::RetainedWindowsEvidence { primary, .. } => {
                primary.kind()
            }
        }
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn is_windows_privilege_cleanup_failure(&self) -> bool {
        matches!(
            self.inner.as_ref(),
            WorkerDirectoryCreationErrorInner::RetainedWindowsEvidence {
                privilege_cleanup_failed: true,
                ..
            }
        )
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn retained_creation_evidence_count(&self) -> usize {
        match self.inner.as_ref() {
            WorkerDirectoryCreationErrorInner::RetainedWindowsEvidence { evidence, .. } => {
                evidence.retained_count()
            }
            WorkerDirectoryCreationErrorInner::Native(_) => 0,
        }
    }

    #[cfg(all(target_os = "windows", test))]
    pub(crate) fn retained_unresolved_creation_evidence_count(&self) -> usize {
        match self.inner.as_ref() {
            WorkerDirectoryCreationErrorInner::RetainedWindowsEvidence { evidence, .. } => {
                evidence.unresolved_count()
            }
            WorkerDirectoryCreationErrorInner::Native(_) => 0,
        }
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn bind_retained_creation_evidence_after_reverify<Value, BindingError>(
        &self,
        bind: impl for<'authority> FnOnce(
            VerifiedWorkerDirectoryFailureBinding<'authority>,
        ) -> Result<Value, BindingError>,
    ) -> Result<Value, WorkerDirectoryFailureBindingError<BindingError>> {
        let WorkerDirectoryCreationErrorInner::RetainedWindowsEvidence { evidence, .. } =
            self.inner.as_ref()
        else {
            return Err(WorkerDirectoryFailureBindingError::NoRetainedEvidence);
        };
        let observations = platform_impl::reverify_worker_directory_failure_evidence(evidence)
            .map_err(WorkerDirectoryFailureBindingError::Reverification)?;
        bind(VerifiedWorkerDirectoryFailureBinding {
            nodes: &observations,
            _authority: evidence,
        })
        .map_err(WorkerDirectoryFailureBindingError::Binding)
    }
}

impl From<std::io::Error> for WorkerDirectoryCreationError {
    fn from(error: std::io::Error) -> Self {
        Self::native(error)
    }
}

impl std::fmt::Debug for WorkerDirectoryCreationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.inner.as_ref() {
            WorkerDirectoryCreationErrorInner::Native(error) => formatter
                .debug_tuple("WorkerDirectoryCreationError")
                .field(error)
                .finish(),
            #[cfg(target_os = "windows")]
            WorkerDirectoryCreationErrorInner::RetainedWindowsEvidence {
                primary,
                operation_error,
                privilege_cleanup_failed,
                evidence,
            } => formatter
                .debug_struct("WorkerDirectoryCreationError")
                .field("primary", primary)
                .field("operation_error", operation_error)
                .field("privilege_cleanup_failed", privilege_cleanup_failed)
                .field("retained_creation_count", &evidence.retained_count())
                .finish_non_exhaustive(),
        }
    }
}

impl std::fmt::Display for WorkerDirectoryCreationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.inner.as_ref() {
            WorkerDirectoryCreationErrorInner::Native(error) => error.fmt(formatter),
            #[cfg(target_os = "windows")]
            WorkerDirectoryCreationErrorInner::RetainedWindowsEvidence {
                primary,
                operation_error: Some(operation_error),
                ..
            } => write!(
                formatter,
                "{primary}; worker directory mutation also failed: {operation_error}"
            ),
            #[cfg(target_os = "windows")]
            WorkerDirectoryCreationErrorInner::RetainedWindowsEvidence {
                primary,
                operation_error: None,
                ..
            } => primary.fmt(formatter),
        }
    }
}

impl std::error::Error for WorkerDirectoryCreationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.inner.as_ref() {
            WorkerDirectoryCreationErrorInner::Native(error) => Some(error),
            #[cfg(target_os = "windows")]
            WorkerDirectoryCreationErrorInner::RetainedWindowsEvidence { primary, .. } => {
                Some(primary)
            }
        }
    }
}

#[allow(dead_code)] // Consumed by the deferred T0.14 receipt binding integration.
pub(crate) struct VerifiedWorkerDirectoryBinding<'authority> {
    nodes: &'authority [WorkerDirectoryNodeObservation; 6],
    lease: &'authority platform_impl::WorkerDirectoryLease,
}

#[derive(Debug)]
#[allow(dead_code)] // Consumed by the deferred T0.14 receipt binding integration.
pub(crate) enum WorkerDirectoryBindingError<BindingError> {
    Reverification(std::io::Error),
    Binding(BindingError),
    AuthorityRetirement(std::io::Error),
}

impl std::fmt::Debug for WorkerDirectoryCreation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerDirectoryCreation")
            .field("nodes", &self.nodes)
            .finish_non_exhaustive()
    }
}

#[allow(dead_code)] // Consumed by the deferred T0.14 receipt integration.
impl WorkerDirectoryCreation {
    pub(in crate::platform) fn new(
        root: WorkerDirectoryNodeObservation,
        children: [WorkerDirectoryNodeObservation; 5],
        lease: platform_impl::WorkerDirectoryLease,
    ) -> Self {
        let [repos, jobs, cache, artifacts, logs] = children;
        Self {
            nodes: [root, repos, jobs, cache, artifacts, logs],
            lease,
        }
    }

    pub(crate) fn bind_after_reverify<Value, BindingError>(
        self,
        bind: impl for<'authority> FnOnce(
            VerifiedWorkerDirectoryBinding<'authority>,
        ) -> Result<Value, BindingError>,
    ) -> Result<Value, WorkerDirectoryBindingError<BindingError>> {
        platform_impl::reverify_worker_directory_lease(&self.lease, &self.nodes)
            .map_err(WorkerDirectoryBindingError::Reverification)?;
        let value = bind(VerifiedWorkerDirectoryBinding {
            nodes: &self.nodes,
            lease: &self.lease,
        })
        .map_err(WorkerDirectoryBindingError::Binding)?;
        platform_impl::retire_worker_directory_authority(&self.lease)
            .map_err(WorkerDirectoryBindingError::AuthorityRetirement)?;
        Ok(value)
    }
}

#[allow(dead_code)] // Consumed by the deferred T0.14 receipt binding integration.
impl VerifiedWorkerDirectoryBinding<'_> {
    pub(crate) fn observations(&self) -> &[WorkerDirectoryNodeObservation; 6] {
        self.nodes
    }

    #[cfg(test)]
    fn reverify_retained_authority_for_test(&self) -> std::io::Result<()> {
        platform_impl::reverify_worker_directory_lease(self.lease, self.nodes)
    }
}

#[cfg(target_os = "windows")]
#[allow(dead_code)] // Consumed by the deferred T0.14 receipt binding integration.
impl VerifiedWorkerDirectoryFailureBinding<'_> {
    pub(crate) fn observations(&self) -> &[WorkerDirectoryNodeObservation] {
        self.nodes
    }
}

#[allow(dead_code)] // Consumed by the T0.14 setup action integration follow-up.
impl WorkerDirectoryLayout {
    fn new(
        scope: InstallationScope,
        root: PathBuf,
        creation_policy: WorkerRootCreationPolicy,
        principal: WorkerPrincipal,
    ) -> Self {
        Self {
            scope,
            repos: root.join("repos"),
            jobs: root.join("jobs"),
            cache: root.join("cache"),
            artifacts: root.join("artifacts"),
            logs: root.join("logs"),
            root,
            creation_policy,
            principal,
            #[cfg(test)]
            principal_revalidation: None,
        }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn repos(&self) -> &Path {
        &self.repos
    }

    pub(crate) fn jobs(&self) -> &Path {
        &self.jobs
    }

    pub(crate) fn cache(&self) -> &Path {
        &self.cache
    }

    pub(crate) fn artifacts(&self) -> &Path {
        &self.artifacts
    }

    pub(crate) fn logs(&self) -> &Path {
        &self.logs
    }

    /// Returns every path the native materializer may create, in exact
    /// outer-to-inner creation order. Support ordinals are stable indexes into
    /// the standard-directory ancestors between the retained anchor and root.
    pub(crate) fn materialization_nodes(&self) -> Vec<WorkerDirectoryNode> {
        let mut nodes = self
            .support_paths()
            .into_iter()
            .enumerate()
            .map(|(ordinal, _)| WorkerDirectoryNode::Support {
                ordinal: u16::try_from(ordinal)
                    .expect("native worker path cannot contain more than u16::MAX components"),
            })
            .collect::<Vec<_>>();
        nodes.extend([
            WorkerDirectoryNode::Root,
            WorkerDirectoryNode::Repos,
            WorkerDirectoryNode::Jobs,
            WorkerDirectoryNode::Cache,
            WorkerDirectoryNode::Artifacts,
            WorkerDirectoryNode::Logs,
        ]);
        nodes
    }

    /// Resolves a closed node only when it belongs to this exact layout.
    pub(crate) fn path_for_node(&self, node: WorkerDirectoryNode) -> Option<PathBuf> {
        match node {
            WorkerDirectoryNode::Support { ordinal } => {
                self.support_paths().get(usize::from(ordinal)).cloned()
            }
            WorkerDirectoryNode::Root => Some(self.root.clone()),
            WorkerDirectoryNode::Repos => Some(self.repos.clone()),
            WorkerDirectoryNode::Jobs => Some(self.jobs.clone()),
            WorkerDirectoryNode::Cache => Some(self.cache.clone()),
            WorkerDirectoryNode::Artifacts => Some(self.artifacts.clone()),
            WorkerDirectoryNode::Logs => Some(self.logs.clone()),
        }
    }

    fn support_paths(&self) -> Vec<PathBuf> {
        let WorkerRootCreationPolicy::CreateMissingFrom(anchor) = &self.creation_policy else {
            return Vec::new();
        };
        let Ok(relative) = self.root.strip_prefix(anchor) else {
            return Vec::new();
        };
        let components = relative.components().collect::<Vec<_>>();
        let mut path = anchor.clone();
        components
            .iter()
            .take(components.len().saturating_sub(1))
            .map(|component| {
                path.push(component.as_os_str());
                path.clone()
            })
            .collect()
    }

    fn child_names() -> [&'static str; 5] {
        ["repos", "jobs", "cache", "artifacts", "logs"]
    }
}

#[allow(dead_code)] // Consumed by the T0.14 setup action integration follow-up.
pub(crate) fn resolve_worker_directory_layout(
    scope: InstallationScope,
    principal: &WorkerPrincipal,
    override_root: Option<&Path>,
) -> std::io::Result<WorkerDirectoryLayout> {
    if scope == InstallationScope::User
        && principal.account_policy() != WorkerAccountPolicy::CurrentUser
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "user-scope worker must use the current-user account policy",
        ));
    }
    platform_impl::validate_worker_root_principal(scope, principal)?;
    let (root, creation_policy) = if let Some(root) = override_root {
        validate_worker_root_override(root)?;
        (
            root.to_path_buf(),
            WorkerRootCreationPolicy::ExistingParent {
                allow_untrusted_parent_create: false,
            },
        )
    } else {
        platform_impl::default_worker_root(scope, principal)?
    };
    Ok(WorkerDirectoryLayout::new(
        scope,
        root,
        creation_policy,
        principal.clone(),
    ))
}

fn validate_revalidated_worker_principal(
    scope: InstallationScope,
    expected: &WorkerPrincipal,
    resolved: std::io::Result<WorkerPrincipal>,
    current: Option<&WorkerPrincipal>,
) -> std::io::Result<WorkerPrincipal> {
    let resolved = resolved.map_err(|_error| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "worker principal could not be revalidated before filesystem mutation",
        )
    })?;
    if &resolved != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "worker principal identity or name drifted before filesystem mutation",
        ));
    }
    if scope == InstallationScope::User {
        let current = current.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "current user could not be revalidated before filesystem mutation",
            )
        })?;
        validate_user_scope_principal(expected, current)?;
    }
    Ok(resolved)
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn validate_windows_restore_privilege_result(
    owner_matches_current: bool,
    adjustment_succeeded: bool,
    last_error: u32,
) -> std::io::Result<bool> {
    const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;

    if owner_matches_current {
        return Ok(false);
    }
    if !adjustment_succeeded {
        return Err(std::io::Error::from_raw_os_error(last_error as i32));
    }
    if last_error == ERROR_NOT_ALL_ASSIGNED {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "SeRestorePrivilege is unavailable for dedicated worker ownership",
        ));
    }
    if last_error != 0 {
        return Err(std::io::Error::from_raw_os_error(last_error as i32));
    }
    Ok(true)
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
struct WindowsPrivilegedWorkerMutation<Evidence> {
    operation_error: Option<std::io::Error>,
    evidence: Evidence,
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
enum WindowsPrivilegedWorkerMutationResolution<Evidence> {
    Success(Evidence),
    OperationFailure {
        error: std::io::Error,
        evidence: Evidence,
    },
    Failure {
        operation_error: Option<std::io::Error>,
        cleanup_error: std::io::Error,
        evidence: Evidence,
    },
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn reconcile_windows_privileged_worker_mutation<Evidence>(
    mutation: WindowsPrivilegedWorkerMutation<Evidence>,
    cleanup: std::io::Result<()>,
) -> WindowsPrivilegedWorkerMutationResolution<Evidence> {
    match (mutation.operation_error, cleanup) {
        (operation_error, Err(cleanup_error)) => {
            WindowsPrivilegedWorkerMutationResolution::Failure {
                operation_error,
                cleanup_error,
                evidence: mutation.evidence,
            }
        }
        (Some(error), Ok(())) => WindowsPrivilegedWorkerMutationResolution::OperationFailure {
            error,
            evidence: mutation.evidence,
        },
        (None, Ok(())) => WindowsPrivilegedWorkerMutationResolution::Success(mutation.evidence),
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
struct WindowsPrivilegeRestorer<State> {
    previous: State,
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
impl<State> WindowsPrivilegeRestorer<State> {
    fn new(previous: State) -> Self {
        Self { previous }
    }

    fn restore<Error>(self, restore: impl FnOnce(State) -> Result<(), Error>) -> Result<(), Error> {
        restore(self.previous)
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn validate_windows_worker_lock_anchor_identity(
    expected: WorkerDirectoryIdentity,
    actual: WorkerDirectoryIdentity,
) -> std::io::Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows worker lock anchor identity changed before filesystem mutation",
        ))
    }
}

/// Creates the fixed worker layout without enumerating or rewriting descendants.
///
/// Ownership assignment for a future dedicated principal is intentionally a
/// separate setup action; this primitive never recursively changes metadata.
#[allow(dead_code)] // Consumed by the T0.14 setup action integration follow-up.
pub(crate) fn create_worker_directory_layout(
    layout: &WorkerDirectoryLayout,
) -> Result<WorkerDirectoryCreation, WorkerDirectoryCreationError> {
    #[cfg(target_os = "windows")]
    {
        platform_impl::create_worker_directory_layout(layout)
    }
    #[cfg(not(target_os = "windows"))]
    {
        platform_impl::create_worker_directory_layout(layout).map_err(Into::into)
    }
}

#[allow(dead_code)] // Reached through the deferred T0.14 action integration.
fn validate_worker_root_override(root: &Path) -> std::io::Result<()> {
    if !root.is_absolute()
        || root.file_name().is_none()
        || root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || !platform_impl::worker_root_path_is_normalized(root)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "worker root override must be a normalized absolute non-root path",
        ));
    }
    Ok(())
}

#[allow(dead_code)] // Used by the Windows adapter and its cross-host pure policy test.
fn windows_worker_root_text_is_normalized(units: &[u16]) -> bool {
    if units.len() < 4
        || !matches!(units[0], 0x0041..=0x005a | 0x0061..=0x007a)
        || units[1] != b':' as u16
        || units[2] != b'\\' as u16
        || units.contains(&0)
    {
        return false;
    }

    units[3..]
        .split(|unit| *unit == b'\\' as u16)
        .all(windows_worker_component_is_normalized)
}

fn windows_worker_component_is_normalized(component: &[u16]) -> bool {
    if component.is_empty()
        || matches!(component.last(), Some(unit) if *unit == b'.' as u16 || *unit == b' ' as u16)
        || component.iter().any(|unit| {
            *unit <= 31
                || matches!(
                    *unit,
                    unit if unit == b'<' as u16
                        || unit == b'>' as u16
                        || unit == b':' as u16
                        || unit == b'"' as u16
                        || unit == b'/' as u16
                        || unit == b'|' as u16
                        || unit == b'?' as u16
                        || unit == b'*' as u16
                )
        })
    {
        return false;
    }

    let base = &component[..component
        .iter()
        .position(|unit| *unit == b'.' as u16)
        .unwrap_or(component.len())];
    let base = base
        .iter()
        .rposition(|unit| *unit != b' ' as u16 && *unit != b'.' as u16)
        .map_or(&[][..], |last| &base[..=last]);
    !windows_reserved_dos_name(base)
}

fn windows_reserved_dos_name(name: &[u16]) -> bool {
    if [
        b"CON".as_slice(),
        b"PRN",
        b"AUX",
        b"NUL",
        b"CONIN$",
        b"CONOUT$",
        b"CLOCK$",
    ]
    .into_iter()
    .any(|expected| windows_utf16_eq_ascii(name, expected))
    {
        return true;
    }
    name.len() == 4
        && (windows_utf16_eq_ascii(&name[..3], b"COM")
            || windows_utf16_eq_ascii(&name[..3], b"LPT"))
        && matches!(name[3], 0x0031..=0x0039 | 0x00b9 | 0x00b2 | 0x00b3)
}

fn windows_utf16_eq_ascii(actual: &[u16], expected: &[u8]) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            u8::try_from(*actual).is_ok_and(|actual| actual.eq_ignore_ascii_case(expected))
        })
}

#[allow(dead_code)] // Reached through the deferred T0.14 action integration.
fn validate_user_scope_principal(
    selected: &WorkerPrincipal,
    current: &WorkerPrincipal,
) -> std::io::Result<()> {
    if selected.account_policy() != WorkerAccountPolicy::CurrentUser {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "user-scope worker must use the current-user account policy",
        ));
    }
    if selected != current {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "user-scope worker must be the current native principal",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PrincipalKind {
    UnixUid,
    WindowsSid,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WorkerAccountPolicy {
    CurrentUser,
    Dedicated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WorkerIsolation {
    SharedUser,
    DedicatedAccount,
}

/// A validated, stable native account identity.
///
/// Keep this type free of `Display`: callers must choose deliberately whether
/// a diagnostic needs the account name or native identifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct WorkerPrincipal {
    principal_kind: PrincipalKind,
    principal_id: String,
    name: String,
    account_policy: WorkerAccountPolicy,
}

impl WorkerPrincipal {
    pub(crate) fn new(
        principal_kind: PrincipalKind,
        principal_id: impl Into<String>,
        name: impl Into<String>,
        account_policy: WorkerAccountPolicy,
    ) -> std::io::Result<Self> {
        let principal_id = principal_id.into();
        let name = name.into();
        validate_principal_name(principal_kind, &name)?;
        match principal_kind {
            PrincipalKind::UnixUid => validate_unix_uid(&principal_id)?,
            PrincipalKind::WindowsSid => validate_windows_sid(&principal_id)?,
        }
        Ok(Self {
            principal_kind,
            principal_id,
            name,
            account_policy,
        })
    }

    pub(crate) fn principal_kind(&self) -> PrincipalKind {
        self.principal_kind
    }

    #[allow(dead_code)] // Used by platform-specific authorization and integration contracts.
    pub(crate) fn principal_id(&self) -> &str {
        &self.principal_id
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn account_policy(&self) -> WorkerAccountPolicy {
        self.account_policy
    }

    pub(crate) fn isolation(&self) -> WorkerIsolation {
        match self.account_policy {
            WorkerAccountPolicy::CurrentUser => WorkerIsolation::SharedUser,
            WorkerAccountPolicy::Dedicated => WorkerIsolation::DedicatedAccount,
        }
    }

    #[cfg(unix)]
    pub(crate) fn unix_uid(&self) -> std::io::Result<u32> {
        if self.principal_kind != PrincipalKind::UnixUid {
            return Err(invalid_principal("worker principal is not a Unix uid"));
        }
        self.principal_id
            .parse::<u32>()
            .map_err(|_| invalid_principal("worker uid is invalid"))
    }
}

impl<'de> Deserialize<'de> for WorkerPrincipal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            principal_kind: PrincipalKind,
            principal_id: String,
            name: String,
            account_policy: WorkerAccountPolicy,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.principal_kind,
            wire.principal_id,
            wire.name,
            wire.account_policy,
        )
        .map_err(serde::de::Error::custom)
    }
}

fn validate_unix_uid(value: &str) -> std::io::Result<()> {
    let uid = value
        .parse::<u32>()
        .map_err(|_| invalid_principal("worker uid must be canonical decimal u32 text"))?;
    if uid == 0 || uid.to_string() != value {
        return Err(invalid_principal(
            "worker uid must be canonical non-root decimal text",
        ));
    }
    Ok(())
}

fn validate_windows_sid(value: &str) -> std::io::Result<()> {
    let Some(rest) = value.strip_prefix("S-1-") else {
        return Err(invalid_principal("worker SID must use canonical S-1 text"));
    };
    let components = rest.split('-').collect::<Vec<_>>();
    if !(2..=16).contains(&components.len()) {
        return Err(invalid_principal(
            "worker SID has an invalid component count",
        ));
    }
    let authority = canonical_decimal(components[0], u64::MAX)?;
    if authority > 0x0000_ffff_ffff_ffff {
        return Err(invalid_principal("worker SID authority is out of range"));
    }
    for component in &components[1..] {
        canonical_decimal(component, u32::MAX as u64)?;
    }
    if value == "S-1-5-18" {
        return Err(invalid_principal("SYSTEM cannot be a worker principal"));
    }
    Ok(())
}

fn canonical_decimal(value: &str, maximum: u64) -> std::io::Result<u64> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| invalid_principal("native principal identifier is not decimal"))?;
    if parsed > maximum || parsed.to_string() != value {
        return Err(invalid_principal(
            "native principal identifier is not canonical",
        ));
    }
    Ok(parsed)
}

fn validate_principal_name(_kind: PrincipalKind, value: &str) -> std::io::Result<()> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(invalid_principal("worker account name is invalid"));
    }
    // The stable native id, not a locally invented login-name grammar, is the
    // authority. NSS and directory services legitimately return names outside
    // traditional `useradd` syntax (for example numeric-leading or `$` names).
    // Exclude only values that are ambiguous at filesystem/serialization
    // boundaries; the platform adapter separately proves the exact id/name map.
    let valid = !value
        .bytes()
        .any(|byte| matches!(byte, b'\\' | b'/' | b':'));
    if !valid {
        return Err(invalid_principal("worker account name is ambiguous"));
    }
    Ok(())
}

fn invalid_principal(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}

#[allow(dead_code)] // The setup orchestrator consumes all three host classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SetupHostPrivilege {
    Ordinary,
    Root,
    Administrator,
}

/// Native setup identity captured before any mutation.
///
/// The execution token is intentionally opaque, non-serializable, and not
/// `Debug`: it is authority, not request data.
#[allow(dead_code)] // The T0.12 setup orchestrator consumes this boundary.
pub(crate) struct SetupExecutionContext {
    host_privilege: SetupHostPrivilege,
    original_principal: WorkerPrincipal,
    user_token: UserExecutionToken,
}

#[allow(dead_code)] // The T0.12 setup orchestrator passes this to user-phase execution.
pub(crate) struct UserExecutionToken(platform_impl::UserExecutionToken);

#[allow(dead_code)]
impl UserExecutionToken {
    pub(crate) fn run_user_phase(
        &self,
        request: &[u8],
    ) -> std::io::Result<std::process::ExitStatus> {
        platform_impl::run_user_phase(&self.0, request)
    }
}

#[allow(dead_code)]
impl SetupExecutionContext {
    pub(crate) fn capture() -> std::io::Result<Self> {
        platform_impl::capture_setup_execution_context()
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        host_privilege: SetupHostPrivilege,
        original_principal: WorkerPrincipal,
    ) -> Self {
        assert_eq!(
            original_principal,
            resolve_current_worker_principal().unwrap(),
            "test execution tokens may only represent the actual current principal"
        );
        let user_token = platform_impl::test_user_execution_token(&original_principal);
        Self::new(host_privilege, original_principal, user_token)
    }

    #[cfg(test)]
    pub(crate) fn with_original_principal_for_test(
        mut self,
        original_principal: WorkerPrincipal,
    ) -> Self {
        self.original_principal = original_principal;
        self
    }

    fn new(
        host_privilege: SetupHostPrivilege,
        original_principal: WorkerPrincipal,
        user_token: platform_impl::UserExecutionToken,
    ) -> Self {
        Self {
            host_privilege,
            original_principal,
            user_token: UserExecutionToken(user_token),
        }
    }

    pub(crate) fn host_privilege(&self) -> SetupHostPrivilege {
        self.host_privilege
    }

    pub(crate) fn original_principal(&self) -> &WorkerPrincipal {
        &self.original_principal
    }

    pub(crate) fn user_token(&self) -> &UserExecutionToken {
        &self.user_token
    }
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct UnixCallerIds {
    real_uid: u32,
    effective_uid: u32,
    real_gid: u32,
    effective_gid: u32,
}

#[cfg(unix)]
impl UnixCallerIds {
    fn new(real_uid: u32, effective_uid: u32, real_gid: u32, effective_gid: u32) -> Self {
        Self {
            real_uid,
            effective_uid,
            real_gid,
            effective_gid,
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct UnixOriginalIdentity {
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
impl UnixOriginalIdentity {
    fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnixExecutionSelection {
    privilege: SetupHostPrivilege,
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
impl UnixExecutionSelection {
    fn new(privilege: SetupHostPrivilege, uid: u32, gid: u32) -> Self {
        Self {
            privilege,
            uid,
            gid,
        }
    }
}

#[cfg(unix)]
fn select_unix_execution<F>(
    caller: UnixCallerIds,
    elevated_origin: F,
) -> std::io::Result<UnixExecutionSelection>
where
    F: FnOnce() -> std::io::Result<UnixOriginalIdentity>,
{
    if caller.real_uid == caller.effective_uid
        && caller.real_uid != 0
        && caller.real_gid == caller.effective_gid
        && caller.real_gid != 0
    {
        return Ok(UnixExecutionSelection::new(
            SetupHostPrivilege::Ordinary,
            caller.real_uid,
            caller.real_gid,
        ));
    }
    if caller.real_uid == 0
        && caller.effective_uid == 0
        && caller.real_gid == 0
        && caller.effective_gid == 0
    {
        let original = elevated_origin()?;
        if original.uid == 0 || original.gid == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "elevated setup requires an original non-root user and group",
            ));
        }
        return Ok(UnixExecutionSelection::new(
            SetupHostPrivilege::Root,
            original.uid,
            original.gid,
        ));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "ambiguous Unix setup caller identity",
    ))
}

#[cfg(unix)]
fn parse_sudo_origin_entries<I, K, V>(entries: I) -> std::io::Result<(UnixOriginalIdentity, String)>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    let mut uid = None;
    let mut gid = None;
    let mut user = None;
    for (key, value) in entries {
        let slot = if key.as_ref() == std::ffi::OsStr::new("SUDO_UID") {
            Some(&mut uid)
        } else if key.as_ref() == std::ffi::OsStr::new("SUDO_GID") {
            Some(&mut gid)
        } else if key.as_ref() == std::ffi::OsStr::new("SUDO_USER") {
            Some(&mut user)
        } else {
            None
        };
        if let Some(slot) = slot {
            if slot.replace(value.as_ref().to_owned()).is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "elevated setup has ambiguous sudo origin fields",
                ));
            }
        }
    }
    let parse_id = |value: Option<std::ffi::OsString>| -> std::io::Result<u32> {
        let value = value
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "elevated setup is missing a valid sudo origin",
                )
            })?;
        let id = value.parse::<u32>().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "elevated setup has malformed sudo origin ids",
            )
        })?;
        if id.to_string() != value {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "elevated setup has non-canonical sudo origin ids",
            ));
        }
        Ok(id)
    };
    let uid = parse_id(uid)?;
    let gid = parse_id(gid)?;
    let user = user
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "elevated setup is missing a valid sudo original user",
            )
        })?;
    validate_principal_name(PrincipalKind::UnixUid, &user)?;
    Ok((UnixOriginalIdentity::new(uid, gid), user))
}

#[allow(dead_code)]
const SE_GROUP_ENABLED: u32 = 0x0000_0004;
#[allow(dead_code)]
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;

#[allow(dead_code)] // Native Windows capture is an explicit follow-on gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsTokenElevationType {
    Default,
    Full,
    Limited,
}

#[allow(dead_code)] // Native Windows capture is an explicit follow-on gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsIntegrityLevel {
    Low,
    Medium,
    High,
    System,
}

#[allow(dead_code)] // Native Windows capture is an explicit follow-on gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsTokenPosture {
    elevation_type: WindowsTokenElevationType,
    integrity_level: WindowsIntegrityLevel,
    administrators_group_attributes: Option<u32>,
}

#[allow(dead_code)]
impl WindowsTokenPosture {
    pub(crate) fn new(
        elevation_type: WindowsTokenElevationType,
        integrity_level: WindowsIntegrityLevel,
        administrators_group_attributes: Option<u32>,
    ) -> Self {
        Self {
            elevation_type,
            integrity_level,
            administrators_group_attributes,
        }
    }
}

#[allow(dead_code)] // Parsed by the native Windows token adapter.
fn windows_token_posture_from_native(
    elevation_type: u32,
    integrity_rid: u32,
    administrators_group_attributes: Option<u32>,
) -> std::io::Result<WindowsTokenPosture> {
    let elevation_type = match elevation_type {
        1 => WindowsTokenElevationType::Default,
        2 => WindowsTokenElevationType::Full,
        3 => WindowsTokenElevationType::Limited,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Windows returned an unknown token elevation type",
            ));
        }
    };
    let integrity_level = match integrity_rid {
        0x0000..=0x1fff => WindowsIntegrityLevel::Low,
        0x2000..=0x2fff => WindowsIntegrityLevel::Medium,
        0x3000..=0x3fff => WindowsIntegrityLevel::High,
        0x4000..=0x4fff => WindowsIntegrityLevel::System,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Windows token has an unsupported integrity level",
            ));
        }
    };
    Ok(WindowsTokenPosture::new(
        elevation_type,
        integrity_level,
        administrators_group_attributes,
    ))
}

#[allow(dead_code)] // Used by the native Windows UAC adapter.
fn windows_quote_command_argument(argument: &[u16]) -> std::io::Result<Vec<u16>> {
    if argument.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows authorization argument contains a NUL code unit",
        ));
    }
    let mut quoted = Vec::with_capacity(argument.len() + 2);
    quoted.push(u16::from(b'\"'));
    let mut backslashes = 0_usize;
    for &unit in argument {
        if unit == u16::from(b'\\') {
            backslashes += 1;
            continue;
        }
        if unit == u16::from(b'\"') {
            quoted.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2 + 1));
        } else {
            quoted.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
        }
        quoted.push(unit);
        backslashes = 0;
    }
    quoted.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2));
    quoted.push(u16::from(b'\"'));
    Ok(quoted)
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsUserTokenChoice {
    Current,
    LinkedLimited,
}

#[allow(dead_code)]
fn select_windows_user_token(
    current: WindowsTokenPosture,
    linked: Option<WindowsTokenPosture>,
) -> std::io::Result<WindowsUserTokenChoice> {
    let admin_enabled = |posture: WindowsTokenPosture| {
        posture
            .administrators_group_attributes
            .is_some_and(|attributes| attributes & SE_GROUP_ENABLED != 0)
    };
    let admin_deny_only = |posture: WindowsTokenPosture| {
        posture
            .administrators_group_attributes
            .is_some_and(|attributes| {
                attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0 && attributes & SE_GROUP_ENABLED == 0
            })
    };
    let safe_limited = |posture: WindowsTokenPosture| {
        posture.elevation_type == WindowsTokenElevationType::Limited
            && posture.integrity_level == WindowsIntegrityLevel::Medium
            && admin_deny_only(posture)
    };
    let safe_full = |posture: WindowsTokenPosture| {
        posture.elevation_type == WindowsTokenElevationType::Full
            && posture.integrity_level == WindowsIntegrityLevel::High
            && admin_enabled(posture)
    };

    match current.elevation_type {
        WindowsTokenElevationType::Default
            if current.integrity_level == WindowsIntegrityLevel::Medium
                && current.administrators_group_attributes.is_none() =>
        {
            Ok(WindowsUserTokenChoice::Current)
        }
        WindowsTokenElevationType::Limited
            if safe_limited(current) && linked.is_some_and(safe_full) =>
        {
            Ok(WindowsUserTokenChoice::Current)
        }
        WindowsTokenElevationType::Full
            if safe_full(current) && linked.is_some_and(safe_limited) =>
        {
            Ok(WindowsUserTokenChoice::LinkedLimited)
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows has no safe non-elevated medium user token",
        )),
    }
}

fn validated_privileged_phase_arguments(
    executable: &Path,
    request_path: &Path,
    request_digest: &str,
    current_executable: &Path,
) -> std::io::Result<Vec<std::ffi::OsString>> {
    if !executable.is_absolute() || !request_path.is_absolute() || !current_executable.is_absolute()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "setup authorization paths must be absolute",
        ));
    }
    let executable = std::fs::canonicalize(executable)?;
    let current_executable = std::fs::canonicalize(current_executable)?;
    if executable != current_executable {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "setup authorization executable is not the current binary",
        ));
    }
    if request_path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "setup authorization request path is not normalized",
        ));
    }
    if request_path.file_name() != Some(std::ffi::OsStr::new("authorization-request.json"))
        || !authorization_request_path_is_safe_for_argv(request_path)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "setup authorization request path is outside the closed request shape",
        ));
    }
    if request_digest.len() != 64
        || !request_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "setup authorization request digest is invalid",
        ));
    }
    Ok(vec![
        "setup".into(),
        "privileged-phase".into(),
        "--request".into(),
        request_path.as_os_str().to_owned(),
        "--digest".into(),
        request_digest.into(),
    ])
}

fn authorization_request_path_is_safe_for_argv(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    if value.chars().any(char::is_control)
        || value
            .bytes()
            .any(|byte| matches!(byte, b'=' | b'?' | b'#' | b'\'' | b'"'))
    {
        return false;
    }
    let lowered = value.to_ascii_lowercase();
    ![
        "api_key",
        "apikey",
        "auth_key",
        "authkey",
        "password",
        "passwd",
        "private_key",
        "credential",
        "bearer",
        "secret",
        "token",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
}

#[cfg(unix)]
struct UnixAuthorizationInvocation {
    program: PathBuf,
    arguments: Vec<std::ffi::OsString>,
}

#[cfg(unix)]
fn unix_authorization_invocation(
    executable: &Path,
    request_path: &Path,
    request_digest: &str,
    current_executable: &Path,
) -> std::io::Result<UnixAuthorizationInvocation> {
    let child_arguments = validated_privileged_phase_arguments(
        executable,
        request_path,
        request_digest,
        current_executable,
    )?;
    let executable = std::fs::canonicalize(executable)?;
    let mut arguments = Vec::with_capacity(child_arguments.len() + 2);
    arguments.push("--".into());
    arguments.push(executable.as_os_str().to_owned());
    arguments.extend(child_arguments);
    Ok(UnixAuthorizationInvocation {
        program: PathBuf::from("/usr/bin/sudo"),
        arguments,
    })
}

#[cfg(unix)]
pub(crate) fn verify_setup_authorization_executable(executable: &Path) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let executable = std::fs::canonicalize(executable)?;
    let metadata = std::fs::symlink_metadata(&executable)?;
    if !unix_authorization_executable_metadata_is_safe(
        metadata.is_file(),
        metadata.uid(),
        metadata.permissions().mode(),
    ) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "setup authorization requires an immutable system-installed Styrn executable",
        ));
    }
    platform_impl::verify_setup_authorization_path_security(&executable)?;
    let mut current = executable.parent();
    while let Some(ancestor) = current {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "setup authorization executable ancestry is user-writable",
            ));
        }
        platform_impl::verify_setup_authorization_path_security(ancestor)?;
        current = ancestor.parent();
    }
    Ok(executable)
}

#[cfg(unix)]
fn unix_authorization_executable_metadata_is_safe(is_file: bool, uid: u32, mode: u32) -> bool {
    is_file && uid == 0 && mode & 0o111 != 0 && mode & 0o6000 == 0 && mode & 0o022 == 0
}

#[cfg(windows)]
#[allow(dead_code)] // Native Windows authorization is an explicit unavailable gate.
pub(crate) fn verify_setup_authorization_executable(executable: &Path) -> std::io::Result<PathBuf> {
    platform_impl::verify_setup_authorization_executable(executable)
}

#[allow(dead_code)] // Wired by the T0.12 setup orchestrator.
pub(crate) fn invoke_setup_authorization(
    executable: &Path,
    request_path: &Path,
    request_digest: &str,
) -> std::io::Result<std::process::ExitStatus> {
    platform_impl::invoke_setup_authorization(executable, request_path, request_digest)
}

#[cfg(unix)]
fn validate_unix_caller_ids(real_uid: u32, effective_uid: u32) -> std::io::Result<u32> {
    if real_uid == 0 || effective_uid == 0 || real_uid != effective_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "privileged or mismatched caller identity requires an authenticated elevation handoff",
        ));
    }
    Ok(real_uid)
}

#[cfg(test)]
mod principal_tests {
    use super::*;

    #[test]
    fn stable_principal_syntax_is_closed_and_rejects_privileged_ids() {
        assert!(WorkerPrincipal::new(
            PrincipalKind::UnixUid,
            "501",
            "123-build$",
            WorkerAccountPolicy::CurrentUser,
        )
        .is_ok());
        for id in ["", "0", "0501", "4294967296", "-1"] {
            assert!(
                WorkerPrincipal::new(
                    PrincipalKind::UnixUid,
                    id,
                    "worker",
                    WorkerAccountPolicy::CurrentUser,
                )
                .is_err(),
                "{id}"
            );
        }
        assert!(WorkerPrincipal::new(
            PrincipalKind::WindowsSid,
            "S-1-5-21-1-2-3-1001",
            "build.agent$",
            WorkerAccountPolicy::CurrentUser,
        )
        .is_ok());
        for id in [
            "S-1-5-18",
            "s-1-5-21-1",
            "S-01-5-21-1",
            "S-1-05-21-1",
            "S-1-5",
            "S-1-281474976710656-1",
        ] {
            assert!(
                WorkerPrincipal::new(
                    PrincipalKind::WindowsSid,
                    id,
                    "worker",
                    WorkerAccountPolicy::CurrentUser,
                )
                .is_err(),
                "{id}"
            );
        }
        for name in [
            "",
            " worker",
            "worker ",
            "worker\nname",
            "a/b",
            "a\\b",
            "a:b",
        ] {
            assert!(WorkerPrincipal::new(
                PrincipalKind::UnixUid,
                "501",
                name,
                WorkerAccountPolicy::CurrentUser,
            )
            .is_err());
        }
    }

    #[test]
    fn worker_principal_policy_is_intrinsic_and_named_lookup_requires_it() {
        let current = resolve_current_worker_principal().unwrap();
        assert_eq!(current.account_policy(), WorkerAccountPolicy::CurrentUser);
        assert_eq!(current.isolation(), WorkerIsolation::SharedUser);

        let dedicated =
            resolve_named_worker_principal(current.name(), WorkerAccountPolicy::Dedicated).unwrap();
        assert_eq!(dedicated.account_policy(), WorkerAccountPolicy::Dedicated);
        assert_eq!(dedicated.isolation(), WorkerIsolation::DedicatedAccount);
        assert_ne!(current, dedicated);

        let serialized = serde_json::to_string(&dedicated).unwrap();
        assert!(serialized.contains("\"account_policy\":\"dedicated\""));
        assert_eq!(
            serde_json::from_str::<WorkerPrincipal>(&serialized).unwrap(),
            dedicated
        );
    }

    #[test]
    fn user_scope_rejects_dedicated_principal_before_filesystem_mutation() {
        let current = resolve_current_worker_principal().unwrap();
        let dedicated = WorkerPrincipal::new(
            current.principal_kind(),
            current.principal_id(),
            current.name(),
            WorkerAccountPolicy::Dedicated,
        )
        .unwrap();
        let parent = std::env::temp_dir().join(format!(
            "styrn-dedicated-user-scope-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&parent).unwrap();
        let root = parent.join("styrn");

        let error =
            resolve_worker_directory_layout(InstallationScope::User, &dedicated, Some(&root))
                .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!root.exists());
        std::fs::remove_dir(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_caller_policy_accepts_only_equal_nonroot_ids() {
        assert_eq!(validate_unix_caller_ids(501, 501).unwrap(), 501);
        for (real, effective) in [(0, 0), (501, 0), (0, 501), (501, 502)] {
            assert!(validate_unix_caller_ids(real, effective).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_authorization_uses_stable_uid_not_account_name() {
        let first = WorkerPrincipal::new(
            PrincipalKind::UnixUid,
            "501",
            "same-name",
            WorkerAccountPolicy::CurrentUser,
        )
        .unwrap();
        let replacement = WorkerPrincipal::new(
            PrincipalKind::UnixUid,
            "502",
            "same-name",
            WorkerAccountPolicy::CurrentUser,
        )
        .unwrap();
        assert_eq!(first.unix_uid().unwrap(), 501);
        assert_eq!(replacement.unix_uid().unwrap(), 502);
    }

    #[test]
    fn worker_principal_revalidation_rejects_id_name_deletion_and_current_user_drift() {
        let expected = WorkerPrincipal::new(
            PrincipalKind::UnixUid,
            "501",
            "selected-worker",
            WorkerAccountPolicy::CurrentUser,
        )
        .unwrap();
        let reused = WorkerPrincipal::new(
            PrincipalKind::UnixUid,
            "501",
            "replacement",
            WorkerAccountPolicy::CurrentUser,
        )
        .unwrap();
        let renamed = WorkerPrincipal::new(
            PrincipalKind::UnixUid,
            "501",
            "renamed-worker",
            WorkerAccountPolicy::CurrentUser,
        )
        .unwrap();
        let different = WorkerPrincipal::new(
            PrincipalKind::UnixUid,
            "502",
            "different-worker",
            WorkerAccountPolicy::CurrentUser,
        )
        .unwrap();

        assert!(validate_revalidated_worker_principal(
            InstallationScope::System,
            &expected,
            Ok(reused),
            None,
        )
        .is_err());
        assert!(validate_revalidated_worker_principal(
            InstallationScope::System,
            &expected,
            Ok(renamed),
            None,
        )
        .is_err());
        assert!(validate_revalidated_worker_principal(
            InstallationScope::System,
            &expected,
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "account deleted",
            )),
            None,
        )
        .is_err());
        assert!(validate_revalidated_worker_principal(
            InstallationScope::User,
            &expected,
            Ok(expected.clone()),
            Some(&different),
        )
        .is_err());
        assert_eq!(
            validate_revalidated_worker_principal(
                InstallationScope::User,
                &expected,
                Ok(expected.clone()),
                Some(&expected),
            )
            .unwrap(),
            expected,
        );
    }

    #[test]
    fn windows_restore_privilege_policy_skips_current_owner_and_rejects_not_assigned() {
        assert!(!validate_windows_restore_privilege_result(true, false, 1300).unwrap());
        assert!(validate_windows_restore_privilege_result(false, true, 0).unwrap());
        let error = validate_windows_restore_privilege_result(false, true, 1300).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(validate_windows_restore_privilege_result(false, false, 5).is_err());
    }

    #[test]
    fn windows_privilege_cleanup_failure_retains_zero_some_and_all_creation_evidence() {
        for evidence in [vec![], vec![11_u8, 29, 47], vec![1_u8, 2, 3, 4, 5, 6]] {
            let operation_error =
                (evidence.len() < 6).then(|| std::io::Error::other("injected mutation failure"));
            let resolution = reconcile_windows_privileged_worker_mutation(
                WindowsPrivilegedWorkerMutation {
                    operation_error,
                    evidence: evidence.clone(),
                },
                Err(std::io::Error::other(
                    "injected exact-state restoration failure",
                )),
            );

            let WindowsPrivilegedWorkerMutationResolution::Failure {
                operation_error,
                cleanup_error,
                evidence: retained,
            } = resolution
            else {
                panic!("cleanup failure was reported as successful creation");
            };
            assert_eq!(retained, evidence);
            assert_eq!(operation_error.is_some(), retained.len() < 6);
            assert_eq!(cleanup_error.kind(), std::io::ErrorKind::Other);
        }
    }

    #[test]
    fn windows_privilege_restorer_supplies_the_exact_previous_state() {
        let previous = [0x00_u8, 0x11, 0x80, 0xfe, 0x7a, 0x55, 0xaa, 0xff];
        let mut restored = None;

        WindowsPrivilegeRestorer::new(previous)
            .restore(|state| {
                restored = Some(state);
                Ok::<_, std::convert::Infallible>(())
            })
            .unwrap();

        assert_eq!(restored, Some(previous));
    }

    #[test]
    fn windows_worker_mutex_anchor_requires_the_complete_file_identity() {
        let expected = WorkerDirectoryIdentity {
            volume: 0x1020_3040_5060_7080,
            file_id: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
        };
        let mut substituted = expected;
        substituted.file_id[15] ^= 0xff;

        let error = validate_windows_worker_lock_anchor_identity(expected, substituted)
            .expect_err("a high-byte FILE_ID_INFO substitution must be rejected");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(validate_windows_worker_lock_anchor_identity(expected, expected).is_ok());
    }

    #[test]
    fn native_caller_resolution_ignores_spoofable_identity_environment() {
        const CHILD: &str = "STYRN_NATIVE_CALLER_SPOOF_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "platform::principal_tests::native_caller_resolution_ignores_spoofable_identity_environment",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("USER", "forged-root")
                .env("LOGNAME", "forged-root")
                .env("USERNAME", "forged-root")
                .env("SUDO_UID", "0")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "native identity child failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let principal = resolve_current_worker_principal().unwrap();
        assert_ne!(principal.name(), "forged-root");
        #[cfg(unix)]
        assert_eq!(
            principal.principal_id(),
            unsafe { libc::getuid() }.to_string()
        );
    }
}

#[cfg(test)]
mod setup_execution_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn unix_context_ignores_sudo_origin_when_ordinary_and_requires_it_when_root() {
        let ordinary = select_unix_execution(UnixCallerIds::new(501, 501, 20, 20), || {
            panic!("ordinary capture must not inspect SUDO_*")
        })
        .unwrap();
        assert_eq!(
            ordinary,
            UnixExecutionSelection::new(SetupHostPrivilege::Ordinary, 501, 20)
        );

        let root = select_unix_execution(UnixCallerIds::new(0, 0, 0, 0), || {
            Ok(UnixOriginalIdentity::new(501, 20))
        })
        .unwrap();
        assert_eq!(
            root,
            UnixExecutionSelection::new(SetupHostPrivilege::Root, 501, 20)
        );

        assert!(select_unix_execution(UnixCallerIds::new(0, 0, 0, 0), || {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "missing origin",
            ))
        })
        .is_err());
        assert!(
            select_unix_execution(UnixCallerIds::new(501, 0, 20, 0), || {
                Ok(UnixOriginalIdentity::new(501, 20))
            })
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn sudo_origin_requires_exactly_one_consistent_value_per_field() {
        let valid = parse_sudo_origin_entries([
            ("SUDO_UID", "501"),
            ("SUDO_GID", "20"),
            ("SUDO_USER", "alex"),
            ("UNRELATED", "ignored"),
        ])
        .unwrap();
        assert_eq!(valid.0.uid, 501);
        assert_eq!(valid.0.gid, 20);
        assert_eq!(valid.1, "alex");

        for invalid in [
            vec![("SUDO_UID", "501"), ("SUDO_GID", "20")],
            vec![
                ("SUDO_UID", "501"),
                ("SUDO_UID", "502"),
                ("SUDO_GID", "20"),
                ("SUDO_USER", "alex"),
            ],
            vec![
                ("SUDO_UID", "0501"),
                ("SUDO_GID", "20"),
                ("SUDO_USER", "alex"),
            ],
        ] {
            assert!(parse_sudo_origin_entries(invalid).is_err());
        }
    }

    #[test]
    fn windows_token_policy_uses_only_a_medium_limited_user_token() {
        let limited = WindowsTokenPosture::new(
            WindowsTokenElevationType::Limited,
            WindowsIntegrityLevel::Medium,
            Some(SE_GROUP_USE_FOR_DENY_ONLY),
        );
        let full = WindowsTokenPosture::new(
            WindowsTokenElevationType::Full,
            WindowsIntegrityLevel::High,
            Some(SE_GROUP_ENABLED),
        );
        assert_eq!(
            select_windows_user_token(limited, Some(full)).unwrap(),
            WindowsUserTokenChoice::Current
        );
        assert_eq!(
            select_windows_user_token(full, Some(limited)).unwrap(),
            WindowsUserTokenChoice::LinkedLimited
        );

        let standard = WindowsTokenPosture::new(
            WindowsTokenElevationType::Default,
            WindowsIntegrityLevel::Medium,
            None,
        );
        assert_eq!(
            select_windows_user_token(standard, None).unwrap(),
            WindowsUserTokenChoice::Current
        );

        let uac_off_admin = WindowsTokenPosture::new(
            WindowsTokenElevationType::Default,
            WindowsIntegrityLevel::High,
            Some(SE_GROUP_ENABLED),
        );
        assert!(select_windows_user_token(uac_off_admin, None).is_err());
        assert!(select_windows_user_token(full, None).is_err());
    }

    #[test]
    fn windows_native_token_facts_are_parsed_fail_closed() {
        assert_eq!(
            windows_token_posture_from_native(3, 0x2100, Some(SE_GROUP_USE_FOR_DENY_ONLY)).unwrap(),
            WindowsTokenPosture::new(
                WindowsTokenElevationType::Limited,
                WindowsIntegrityLevel::Medium,
                Some(SE_GROUP_USE_FOR_DENY_ONLY),
            )
        );
        assert!(windows_token_posture_from_native(0, 0x2000, None).is_err());
        assert!(windows_token_posture_from_native(1, 0x5000, None).is_err());
    }

    #[test]
    fn windows_authorization_arguments_use_command_line_to_argv_w_quoting() {
        let quote = |argument: &str| {
            String::from_utf16(
                &windows_quote_command_argument(&argument.encode_utf16().collect::<Vec<_>>())
                    .unwrap(),
            )
            .unwrap()
        };
        assert_eq!(
            quote("C:\\Program Files\\Styrn"),
            "\"C:\\Program Files\\Styrn\""
        );
        assert_eq!(quote("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote("a\\"), "\"a\\\\\"");
        assert!(windows_quote_command_argument(&[b'a' as u16, 0, b'b' as u16]).is_err());
    }

    #[test]
    fn privileged_phase_arguments_are_fixed_and_reject_relative_paths() {
        let current = std::env::current_exe().unwrap();
        let request = std::env::temp_dir().join("authorization-request.json");
        let digest = "a".repeat(64);
        assert_eq!(
            validated_privileged_phase_arguments(&current, &request, &digest, &current).unwrap(),
            vec![
                std::ffi::OsString::from("setup"),
                std::ffi::OsString::from("privileged-phase"),
                std::ffi::OsString::from("--request"),
                request.into_os_string(),
                std::ffi::OsString::from("--digest"),
                std::ffi::OsString::from(&digest),
            ]
        );
        assert!(validated_privileged_phase_arguments(
            Path::new("styrn"),
            Path::new("request.json"),
            &digest,
            &current,
        )
        .is_err());
        assert!(validated_privileged_phase_arguments(
            &current,
            Path::new("request.json"),
            &digest,
            &current,
        )
        .is_err());
        let secret_path = std::env::temp_dir()
            .join("api_key=do-not-echo")
            .join("authorization-request.json");
        let error = validated_privileged_phase_arguments(&current, &secret_path, &digest, &current)
            .unwrap_err();
        assert!(!error.to_string().contains("do-not-echo"));

        #[cfg(unix)]
        {
            let request = std::env::temp_dir().join("authorization-request.json");
            let invocation =
                unix_authorization_invocation(&current, &request, &digest, &current).unwrap();
            assert_eq!(invocation.program, PathBuf::from("/usr/bin/sudo"));
            assert_eq!(
                invocation.arguments,
                vec![
                    std::ffi::OsString::from("--"),
                    current.clone().into_os_string(),
                    std::ffi::OsString::from("setup"),
                    std::ffi::OsString::from("privileged-phase"),
                    std::ffi::OsString::from("--request"),
                    request.into_os_string(),
                    std::ffi::OsString::from("--digest"),
                    std::ffi::OsString::from(digest),
                ]
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn authorization_executable_metadata_rejects_exec_time_privilege_gain() {
        assert!(unix_authorization_executable_metadata_is_safe(
            true, 0, 0o100755
        ));
        for mode in [0o104755, 0o102755, 0o100775, 0o100644] {
            assert!(!unix_authorization_executable_metadata_is_safe(
                true, 0, mode
            ));
        }
        assert!(!unix_authorization_executable_metadata_is_safe(
            true, 501, 0o100755
        ));
        assert!(!unix_authorization_executable_metadata_is_safe(
            false, 0, 0o100755
        ));
    }

    #[cfg(unix)]
    #[test]
    fn verified_private_file_removal_rejects_intermediate_directory_substitution() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("verified-remove-swap-{}", std::process::id()));
        let route = root.join("route");
        let request_parent = route.join("requests");
        std::fs::create_dir_all(&request_parent).unwrap();
        std::fs::set_permissions(&request_parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let request = request_parent.join("request.json");
        std::fs::write(&request, b"original").unwrap();
        std::fs::set_permissions(&request, std::fs::Permissions::from_mode(0o600)).unwrap();
        let identity = private_file_identity(&request).unwrap();
        let principal = resolve_current_worker_principal().unwrap();
        let removal = prepare_verified_private_file_removal(
            &request,
            ManifestOwner::CurrentProcess,
            &principal,
            identity,
        )
        .unwrap();

        let original_route = root.join("original-route");
        std::fs::rename(&route, &original_route).unwrap();
        let replacement = root.join("replacement");
        std::fs::create_dir_all(replacement.join("requests")).unwrap();
        let victim = replacement.join("requests/request.json");
        std::fs::write(&victim, b"must survive").unwrap();
        symlink(&replacement, &route).unwrap();

        consume_verified_private_file(removal).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"must survive");
        assert!(!original_route.join("requests/request.json").exists());

        std::fs::remove_file(&route).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_file_removal_parent_mode_is_owner_aware() {
        assert!(private_file_parent_mode_is_valid(
            ManifestOwner::User,
            0o700
        ));
        assert!(!private_file_parent_mode_is_valid(
            ManifestOwner::User,
            0o755
        ));
        assert!(private_file_parent_mode_is_valid(
            ManifestOwner::System,
            0o755
        ));
        assert!(private_file_parent_mode_is_valid(
            ManifestOwner::System,
            0o700
        ));
        assert!(!private_file_parent_mode_is_valid(
            ManifestOwner::System,
            0o775
        ));
        assert!(private_file_parent_mode_is_valid(
            ManifestOwner::CurrentProcess,
            0o755
        ));
        assert!(private_file_parent_mode_is_valid(
            ManifestOwner::CurrentProcess,
            0o700
        ));
        assert!(!private_file_parent_mode_is_valid(
            ManifestOwner::CurrentProcess,
            0o775
        ));
    }

    #[cfg(unix)]
    #[test]
    fn fixed_user_phase_seam_fails_closed_until_typed_protocol_execution_exists() {
        let context = SetupExecutionContext::capture().unwrap();
        let error = context.user_token().run_user_phase(b"{}").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_original_user_command_keeps_the_exact_native_uid() {
        let context = SetupExecutionContext::capture().unwrap();
        assert_eq!(context.host_privilege(), SetupHostPrivilege::Ordinary);
        let output = platform_impl::run_test_program_as_original(
            &context.user_token().0,
            Path::new("/usr/bin/id"),
            &["-u"],
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            context.original_principal().principal_id()
        );
    }

    #[cfg(unix)]
    #[test]
    fn original_user_command_receives_only_the_sanitized_profile_environment() {
        let context = SetupExecutionContext::capture().unwrap();
        let output = platform_impl::run_test_program_as_original(
            &context.user_token().0,
            Path::new("/usr/bin/env"),
            &[],
        )
        .unwrap();
        assert!(output.status.success());
        let output = String::from_utf8(output.stdout).unwrap();
        let environment = output
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(environment.len(), 4);
        assert_eq!(
            environment.get("USER"),
            Some(&context.original_principal().name())
        );
        assert_eq!(
            environment.get("LOGNAME"),
            Some(&context.original_principal().name())
        );
        assert!(environment
            .get("HOME")
            .is_some_and(|home| Path::new(home).is_absolute()));
        assert_eq!(
            environment.get("PATH"),
            Some(&"/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        );
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "environmental: run this test under native sudo with SUDO_UID/GID/USER set"]
    fn native_sudo_launch_recovers_the_original_nonroot_principal() {
        let context = SetupExecutionContext::capture().unwrap();
        assert_eq!(context.host_privilege(), SetupHostPrivilege::Root);
        let original_uid = context.original_principal().unix_uid().unwrap();
        assert_ne!(original_uid, 0);
        let destination = std::env::temp_dir().join(format!(
            "styrn-original-user-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        let output = platform_impl::run_test_program_as_original(
            &context.user_token().0,
            Path::new("/usr/bin/touch"),
            &[destination.to_str().unwrap()],
        )
        .unwrap();
        assert!(output.status.success());
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(&destination).unwrap().uid(), original_uid);
        std::fs::remove_file(destination).unwrap();
    }
}

#[cfg(test)]
mod private_publication_tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn private_publication_refuses_a_displaced_temporary_without_removing_evidence() {
        let parent = unique_private_publication_directory("displaced-temporary");
        std::fs::create_dir(&parent).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let temporary = parent.join("intent.tmp");
        let displaced = parent.join("created-by-styrn");
        let destination = parent.join("intent.json");
        let principal = resolve_current_worker_principal().unwrap();
        let mut publication =
            create_private_publication_file(&temporary, ManifestOwner::CurrentProcess, &principal)
                .unwrap();
        publication.write_all(b"complete intent\n").unwrap();
        std::fs::rename(&temporary, &displaced).unwrap();
        std::fs::write(&temporary, b"external evidence\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let error = publication
            .complete_exact(b"complete intent\n")
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read(&temporary).unwrap(), b"external evidence\n");
        assert_eq!(std::fs::read(&displaced).unwrap(), b"complete intent\n");
        assert!(!destination.exists());
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn complete_private_publication_is_no_replace_and_durable_before_return() {
        let parent = unique_private_publication_directory("durable-no-replace");
        std::fs::create_dir(&parent).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let principal = resolve_current_worker_principal().unwrap();
        let temporary = parent.join("intent.tmp");
        let destination = parent.join("intent.json");
        let mut publication =
            create_private_publication_file(&temporary, ManifestOwner::CurrentProcess, &principal)
                .unwrap();
        publication.write_all(b"complete intent\n").unwrap();
        let complete = publication.complete_exact(b"complete intent\n").unwrap();

        let published = complete.publish_no_replace(&destination).unwrap();

        assert_eq!(published.path(), destination);
        assert_eq!(std::fs::read(&destination).unwrap(), b"complete intent\n");
        assert!(!temporary.exists());

        let second_temporary = parent.join("second.tmp");
        let mut second = create_private_publication_file(
            &second_temporary,
            ManifestOwner::CurrentProcess,
            &principal,
        )
        .unwrap();
        second.write_all(b"must not replace\n").unwrap();
        let error = second
            .complete_exact(b"must not replace\n")
            .unwrap()
            .publish_no_replace(&destination)
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&destination).unwrap(), b"complete intent\n");
        assert_eq!(
            std::fs::read(&second_temporary).unwrap(),
            b"must not replace\n"
        );
        std::fs::remove_dir_all(parent).unwrap();
    }

    fn unique_private_publication_directory(label: &str) -> PathBuf {
        #[cfg(unix)]
        let temporary = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        #[cfg(target_os = "windows")]
        let temporary = std::env::temp_dir();
        temporary.join(format!(
            "styrn-private-publication-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ))
    }
}

#[cfg(test)]
mod worker_directory_tests {
    use super::*;
    use std::collections::BTreeSet;

    const PROFILE_CHILD_ENV: &str = "STYRN_TEST_WORKER_PROFILE_CHILD";
    const PROFILE_EXPECTED_ENV: &str = "STYRN_TEST_WORKER_PROFILE_EXPECTED";
    #[cfg(target_os = "linux")]
    const NATIVE_PROFILE_CHILD_ENV: &str = "STYRN_TEST_WORKER_NATIVE_PROFILE_CHILD";
    #[cfg(unix)]
    const MODE_CHILD_ROOT_ENV: &str = "STYRN_TEST_WORKER_MODE_CHILD_ROOT";
    const CONCURRENT_CHILD_ROOT_ENV: &str = "STYRN_TEST_WORKER_CONCURRENT_CHILD_ROOT";
    #[cfg(target_os = "linux")]
    const XDG_CHILD_ROOT_ENV: &str = "STYRN_TEST_WORKER_XDG_CHILD_ROOT";

    #[test]
    fn system_worker_directory_layout_has_the_exact_cross_scope_contract() {
        let principal = resolve_current_worker_principal().unwrap();
        let layout =
            resolve_worker_directory_layout(InstallationScope::System, &principal, None).unwrap();

        #[cfg(target_os = "linux")]
        let expected_root = Path::new("/srv/styrn");
        #[cfg(target_os = "macos")]
        let expected_root = Path::new("/Users/Shared/Styrn");
        #[cfg(target_os = "windows")]
        let expected_root = Path::new(r"C:\Styrn");

        assert_eq!(layout.root(), expected_root);
        assert_eq!(layout.repos(), expected_root.join("repos"));
        assert_eq!(layout.jobs(), expected_root.join("jobs"));
        assert_eq!(layout.cache(), expected_root.join("cache"));
        assert_eq!(layout.artifacts(), expected_root.join("artifacts"));
        assert_eq!(layout.logs(), expected_root.join("logs"));
    }

    #[test]
    fn worker_directory_materialization_nodes_are_closed_and_map_to_exact_paths() {
        let principal = resolve_current_worker_principal().unwrap();
        #[cfg(unix)]
        let (anchor, root) = (
            PathBuf::from("/native/profile"),
            PathBuf::from("/native/profile/first/second/styrn"),
        );
        #[cfg(target_os = "windows")]
        let (anchor, root) = (
            PathBuf::from(r"C:\native\profile"),
            PathBuf::from(r"C:\native\profile\first\second\Styrn"),
        );
        let layout = WorkerDirectoryLayout::new(
            InstallationScope::User,
            root.clone(),
            WorkerRootCreationPolicy::CreateMissingFrom(anchor.clone()),
            principal,
        );

        assert_eq!(
            layout.materialization_nodes(),
            vec![
                WorkerDirectoryNode::Support { ordinal: 0 },
                WorkerDirectoryNode::Support { ordinal: 1 },
                WorkerDirectoryNode::Root,
                WorkerDirectoryNode::Repos,
                WorkerDirectoryNode::Jobs,
                WorkerDirectoryNode::Cache,
                WorkerDirectoryNode::Artifacts,
                WorkerDirectoryNode::Logs,
            ]
        );
        assert_eq!(
            layout.path_for_node(WorkerDirectoryNode::Support { ordinal: 0 }),
            Some(anchor.join("first"))
        );
        assert_eq!(
            layout.path_for_node(WorkerDirectoryNode::Support { ordinal: 1 }),
            Some(anchor.join("first").join("second"))
        );
        assert_eq!(
            layout.path_for_node(WorkerDirectoryNode::Support { ordinal: 2 }),
            None
        );
        assert_eq!(
            layout.path_for_node(WorkerDirectoryNode::Root),
            Some(root.clone())
        );
        assert_eq!(
            layout.path_for_node(WorkerDirectoryNode::Jobs),
            Some(root.join("jobs"))
        );
    }

    #[test]
    fn user_worker_directory_layout_is_bound_to_the_current_native_profile() {
        #[cfg(target_os = "linux")]
        if std::env::var_os(NATIVE_PROFILE_CHILD_ENV).is_none() {
            let expected = native_profile_home_for_test().join(".local/share/styrn");
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "platform::worker_directory_tests::user_worker_directory_layout_is_bound_to_the_current_native_profile",
                ])
                .env(NATIVE_PROFILE_CHILD_ENV, "1")
                .env(PROFILE_EXPECTED_ENV, expected)
                .env_remove("XDG_DATA_HOME")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let principal = resolve_current_worker_principal().unwrap();
        let layout =
            resolve_worker_directory_layout(InstallationScope::User, &principal, None).unwrap();

        #[cfg(target_os = "linux")]
        let expected_root = PathBuf::from(std::env::var_os(PROFILE_EXPECTED_ENV).unwrap());
        #[cfg(target_os = "macos")]
        let expected_base = native_profile_home_for_test().join("Library/Application Support");
        #[cfg(target_os = "windows")]
        let expected_base = platform_impl::native_profile_data_root_for_test().unwrap();

        #[cfg(any(target_os = "macos", target_os = "windows"))]
        let expected_root = expected_base.join("Styrn");

        assert_eq!(layout.root(), expected_root);
    }

    #[test]
    fn user_worker_root_ignores_spoofed_profile_environment() {
        let forged = std::env::temp_dir().join("styrn-forged-profile");
        if std::env::var_os(PROFILE_CHILD_ENV).is_some() {
            let principal = resolve_current_worker_principal().unwrap();
            let layout =
                resolve_worker_directory_layout(InstallationScope::User, &principal, None).unwrap();
            assert_eq!(
                layout.root(),
                Path::new(&std::env::var_os(PROFILE_EXPECTED_ENV).unwrap())
            );
            return;
        }

        #[cfg(target_os = "linux")]
        let expected = native_profile_home_for_test().join(".local/share/styrn");
        #[cfg(target_os = "macos")]
        let expected = native_profile_home_for_test().join("Library/Application Support/Styrn");
        #[cfg(target_os = "windows")]
        let expected = platform_impl::native_profile_data_root_for_test()
            .unwrap()
            .join("Styrn");

        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "platform::worker_directory_tests::user_worker_root_ignores_spoofed_profile_environment",
            ])
            .env(PROFILE_CHILD_ENV, "1")
            .env(PROFILE_EXPECTED_ENV, expected)
            .env("HOME", &forged)
            .env("LOCALAPPDATA", &forged)
            .env("USERPROFILE", &forged);
        #[cfg(target_os = "linux")]
        child.env_remove("XDG_DATA_HOME");
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn user_worker_root_rejects_a_principal_other_than_the_current_user() {
        #[cfg(unix)]
        let (selected, current) = (
            WorkerPrincipal::new(
                PrincipalKind::UnixUid,
                "501",
                "selected-worker",
                WorkerAccountPolicy::CurrentUser,
            )
            .unwrap(),
            WorkerPrincipal::new(
                PrincipalKind::UnixUid,
                "502",
                "current-worker",
                WorkerAccountPolicy::CurrentUser,
            )
            .unwrap(),
        );
        #[cfg(target_os = "windows")]
        let (selected, current) = (
            WorkerPrincipal::new(
                PrincipalKind::WindowsSid,
                "S-1-5-21-1-2-3-1001",
                "selected-worker",
                WorkerAccountPolicy::CurrentUser,
            )
            .unwrap(),
            WorkerPrincipal::new(
                PrincipalKind::WindowsSid,
                "S-1-5-21-1-2-3-1002",
                "current-worker",
                WorkerAccountPolicy::CurrentUser,
            )
            .unwrap(),
        );

        let error = validate_user_scope_principal(&selected, &current).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn stale_principal_lookup_seam_fails_before_worker_filesystem_mutation() {
        let expected = resolve_current_worker_principal().unwrap();
        let renamed = WorkerPrincipal::new(
            expected.principal_kind(),
            expected.principal_id(),
            "renamed-worker",
            expected.account_policy(),
        )
        .unwrap();
        #[cfg(unix)]
        let replacement = WorkerPrincipal::new(
            PrincipalKind::UnixUid,
            if expected.principal_id() == "1" {
                "2"
            } else {
                "1"
            },
            expected.name(),
            expected.account_policy(),
        )
        .unwrap();
        #[cfg(target_os = "windows")]
        let replacement = WorkerPrincipal::new(
            PrincipalKind::WindowsSid,
            "S-1-5-21-1-2-3-1001",
            expected.name(),
            expected.account_policy(),
        )
        .unwrap();
        let cases = [
            (
                InstallationScope::System,
                WorkerPrincipalRevalidationTest::Resolved {
                    principal: renamed,
                    current: None,
                },
            ),
            (
                InstallationScope::System,
                WorkerPrincipalRevalidationTest::Resolved {
                    principal: replacement.clone(),
                    current: None,
                },
            ),
            (
                InstallationScope::System,
                WorkerPrincipalRevalidationTest::Deleted,
            ),
            (
                InstallationScope::User,
                WorkerPrincipalRevalidationTest::Resolved {
                    principal: expected.clone(),
                    current: Some(replacement),
                },
            ),
        ];

        for (index, (scope, revalidation)) in cases.into_iter().enumerate() {
            let parent = unique_test_directory(&format!("stale-principal-{index}"));
            std::fs::create_dir(&parent).unwrap();
            let root = parent.join("chosen-root");
            let mut layout =
                resolve_worker_directory_layout(scope, &expected, Some(&root)).unwrap();
            layout.principal_revalidation = Some(revalidation);

            let error = create_worker_directory_layout(&layout).unwrap_err();

            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(directory_entry_names(&parent).is_empty());
            std::fs::remove_dir(parent).unwrap();
        }
    }

    #[test]
    fn absolute_worker_root_override_is_the_exact_root_not_a_parent_prefix() {
        let principal = resolve_current_worker_principal().unwrap();
        let root = std::env::temp_dir().join(format!(
            "styrn-worker-root-override-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));

        let layout =
            resolve_worker_directory_layout(InstallationScope::System, &principal, Some(&root))
                .unwrap();

        assert_eq!(layout.root(), root);
        assert_eq!(layout.repos(), root.join("repos"));
        assert_eq!(layout.logs(), root.join("logs"));
    }

    #[test]
    fn worker_root_override_rejects_relative_non_normalized_and_filesystem_roots() {
        let principal = resolve_current_worker_principal().unwrap();
        #[cfg(unix)]
        let invalid = [
            Path::new("relative/worker"),
            Path::new("/tmp/../worker"),
            Path::new("/tmp/./worker"),
            Path::new("/"),
        ];
        #[cfg(target_os = "windows")]
        let invalid = [
            Path::new(r"relative\worker"),
            Path::new(r"C:\temp\..\worker"),
            Path::new(r"C:\temp\.\worker"),
            Path::new(r"C:\"),
            Path::new(r"C:\work\root."),
            Path::new(r"C:\work\root "),
            Path::new(r"C:\work\CON.logs"),
            Path::new(r"C:\work\LPT9"),
            Path::new(r"C:\work\bad|name"),
            Path::new(r"C:/work\mixed"),
            Path::new(r"\\server\share\worker"),
            Path::new(r"\\?\C:\work\worker"),
        ];

        for root in invalid {
            let error =
                resolve_worker_directory_layout(InstallationScope::System, &principal, Some(root))
                    .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{root:?}");
        }
    }

    #[test]
    fn windows_worker_root_text_rejects_win32_alias_and_device_spellings() {
        for valid in [r"C:\Styrn", r"z:\Worker Data\build.cache"] {
            assert!(
                windows_worker_root_text_is_normalized(&valid.encode_utf16().collect::<Vec<_>>()),
                "{valid:?}"
            );
        }
        for invalid in [
            r"C:\Styrn.",
            r"C:\Styrn ",
            r"C:\CON",
            r"C:\con.logs",
            r"C:\CON .logs",
            r"C:\AUX.tar",
            r"C:\NUL.txt",
            r"C:\LPT9.cache",
            "C:\\COM\u{00b9}\\jobs",
            r"C:\COM1\jobs",
            r"C:\bad<name",
            r#"C:\bad"name"#,
            r"C:\bad*name",
            r"C:\bad|name",
            r"C:\bad:name",
            r"C:/mixed\separators",
            r"\\server\share\Styrn",
            r"\\?\C:\Styrn",
            r"\\.\C:\Styrn",
            r"C:\Styrn\\jobs",
        ] {
            assert!(
                !windows_worker_root_text_is_normalized(
                    &invalid.encode_utf16().collect::<Vec<_>>()
                ),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn worker_directory_creation_creates_only_the_root_and_five_direct_children() {
        let principal = resolve_current_worker_principal().unwrap();
        let parent = unique_test_directory("exact-layout");
        std::fs::create_dir(&parent).unwrap();
        let root = parent.join("chosen-root");
        let layout =
            resolve_worker_directory_layout(InstallationScope::System, &principal, Some(&root))
                .unwrap();

        create_worker_directory_layout(&layout)
            .unwrap()
            .bind_after_reverify(|_| Ok::<_, ()>(()))
            .unwrap();

        let parent_entries = directory_entry_names(&parent);
        assert_eq!(parent_entries, BTreeSet::from(["chosen-root".to_owned()]));
        let root_entries = directory_entry_names(&root);
        assert_eq!(
            root_entries,
            BTreeSet::from([
                "artifacts".to_owned(),
                "cache".to_owned(),
                "jobs".to_owned(),
                "logs".to_owned(),
                "repos".to_owned(),
            ])
        );
        for entry in root_entries {
            let metadata = std::fs::symlink_metadata(root.join(entry)).unwrap();
            assert!(metadata.is_dir());
            assert!(!metadata.file_type().is_symlink());
        }

        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn worker_directory_creation_reports_created_then_existing_canonical_identities() {
        let principal = resolve_current_worker_principal().unwrap();
        let parent = unique_test_directory("layout-observations");
        std::fs::create_dir(&parent).unwrap();
        let root = parent.join("chosen-root");
        let layout =
            resolve_worker_directory_layout(InstallationScope::System, &principal, Some(&root))
                .unwrap();

        let created = create_worker_directory_layout(&layout)
            .unwrap()
            .bind_after_reverify(|binding| {
                Ok::<_, ()>(
                    binding
                        .observations()
                        .iter()
                        .map(|node| {
                            (
                                node.path().to_path_buf(),
                                node.disposition(),
                                node.identity(),
                            )
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .unwrap();
        let existing = create_worker_directory_layout(&layout)
            .unwrap()
            .bind_after_reverify(|binding| {
                Ok::<_, ()>(
                    binding
                        .observations()
                        .iter()
                        .map(|node| {
                            (
                                node.path().to_path_buf(),
                                node.disposition(),
                                node.identity(),
                            )
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .unwrap();

        let expected_paths = std::iter::once(root.clone())
            .chain(
                WorkerDirectoryLayout::child_names()
                    .into_iter()
                    .map(|name| root.join(name)),
            )
            .collect::<Vec<_>>();
        assert_eq!(created.len(), 6);
        assert_eq!(existing.len(), 6);
        for ((created, existing), expected_path) in
            created.iter().zip(&existing).zip(expected_paths)
        {
            assert_eq!(created.0, expected_path);
            assert_eq!(created.1, WorkerDirectoryNodeDisposition::Created);
            assert_eq!(existing.0, created.0);
            assert_eq!(existing.1, WorkerDirectoryNodeDisposition::Existing);
            assert_eq!(existing.2, created.2);
        }

        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn retained_worker_creation_reverify_rejects_path_substitution_before_release() {
        let principal = resolve_current_worker_principal().unwrap();
        let parent = unique_test_directory("retained-layout-substitution");
        std::fs::create_dir(&parent).unwrap();
        let root = parent.join("chosen-root");
        let displaced = parent.join("displaced-root");
        let layout =
            resolve_worker_directory_layout(InstallationScope::System, &principal, Some(&root))
                .unwrap();
        let creation = create_worker_directory_layout(&layout).unwrap();
        std::fs::rename(&root, &displaced).unwrap();
        std::fs::create_dir(&root).unwrap();

        let error = creation
            .bind_after_reverify(|_| Ok::<_, ()>(()))
            .unwrap_err();

        assert!(matches!(
            error,
            WorkerDirectoryBindingError::Reverification(error)
                if error.kind() == std::io::ErrorKind::PermissionDenied
        ));
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn worker_directory_binding_retains_handles_and_preserves_binding_errors() {
        let principal = resolve_current_worker_principal().unwrap();
        let parent = unique_test_directory("retained-binding-authority");
        std::fs::create_dir(&parent).unwrap();
        let root = parent.join("chosen-root");
        let layout =
            resolve_worker_directory_layout(InstallationScope::System, &principal, Some(&root))
                .unwrap();
        let creation = create_worker_directory_layout(&layout).unwrap();

        let error = creation
            .bind_after_reverify(|binding| {
                binding.reverify_retained_authority_for_test().unwrap();
                assert_eq!(binding.observations().len(), 6);
                Err::<(), _>("receipt binding failed")
            })
            .unwrap_err();

        assert!(matches!(
            error,
            WorkerDirectoryBindingError::Binding("receipt binding failed")
        ));
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn worker_directory_rerun_preserves_preexisting_descendants_without_resetting_them() {
        let principal = resolve_current_worker_principal().unwrap();
        let parent = unique_test_directory("preserve-layout");
        let root = parent.join("chosen-root");
        std::fs::create_dir(&parent).unwrap();
        let layout =
            resolve_worker_directory_layout(InstallationScope::System, &principal, Some(&root))
                .unwrap();
        create_worker_directory_layout(&layout)
            .unwrap()
            .bind_after_reverify(|_| Ok::<_, ()>(()))
            .unwrap();
        let repos = root.join("repos");
        let existing = repos.join("existing-project");
        std::fs::create_dir(&existing).unwrap();
        let sentinel = existing.join("sentinel.txt");
        std::fs::write(&sentinel, b"owned before layout creation\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o711)).unwrap();
        }

        create_worker_directory_layout(&layout).unwrap();
        create_worker_directory_layout(&layout).unwrap();

        assert_eq!(
            std::fs::read(&sentinel).unwrap(),
            b"owned before layout creation\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&repos).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&existing).unwrap().permissions().mode() & 0o777,
                0o711
            );
        }

        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn worker_directory_creation_rejects_a_non_directory_child_without_touching_its_contents() {
        let principal = resolve_current_worker_principal().unwrap();
        let parent = unique_test_directory("reject-layout");
        let root = parent.join("chosen-root");
        std::fs::create_dir_all(&root).unwrap();
        let collision = root.join("repos");
        std::fs::write(&collision, b"not a directory\n").unwrap();
        let layout =
            resolve_worker_directory_layout(InstallationScope::System, &principal, Some(&root))
                .unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read(&collision).unwrap(), b"not a directory\n");
        assert_eq!(
            directory_entry_names(&root),
            BTreeSet::from(["repos".to_owned()])
        );

        std::fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn worker_directory_creation_rejects_an_insecure_existing_root_without_mutating_it() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let principal = resolve_current_worker_principal().unwrap();
        let parent = unique_test_directory("insecure-existing-root");
        let root = parent.join("chosen-root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let unrelated = root.join("operator-notes.txt");
        std::fs::write(&unrelated, b"leave this entry alone\n").unwrap();
        let before = std::fs::metadata(&root).unwrap();
        let layout =
            resolve_worker_directory_layout(InstallationScope::System, &principal, Some(&root))
                .unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        let after = std::fs::metadata(&root).unwrap();
        assert_eq!(after.permissions().mode() & 0o777, 0o755);
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(
            std::fs::read(&unrelated).unwrap(),
            b"leave this entry alone\n"
        );
        assert_eq!(
            directory_entry_names(&root),
            BTreeSet::from(["operator-notes.txt".to_owned()])
        );
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn worker_directory_creation_preflights_every_existing_canonical_child() {
        use std::os::unix::fs::PermissionsExt;

        let principal = resolve_current_worker_principal().unwrap();
        let parent = unique_test_directory("insecure-existing-child");
        let root = parent.join("chosen-root");
        let repos = root.join("repos");
        std::fs::create_dir_all(&repos).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&repos, std::fs::Permissions::from_mode(0o750)).unwrap();
        let layout =
            resolve_worker_directory_layout(InstallationScope::System, &principal, Some(&root))
                .unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            directory_entry_names(&root),
            BTreeSet::from(["repos".to_owned()])
        );
        assert_eq!(
            std::fs::metadata(&repos).unwrap().permissions().mode() & 0o777,
            0o750
        );
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn worker_directory_creation_rejects_an_intermediate_symlink_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let principal = resolve_current_worker_principal().unwrap();
        let parent = unique_test_directory("intermediate-symlink");
        let target = unique_test_directory("intermediate-symlink-target");
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&target).unwrap();
        symlink(&target, parent.join("redirected-parent")).unwrap();
        let root = parent.join("redirected-parent/chosen-root");
        let layout =
            resolve_worker_directory_layout(InstallationScope::System, &principal, Some(&root))
                .unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(directory_entry_names(&target).is_empty());

        std::fs::remove_file(parent.join("redirected-parent")).unwrap();
        std::fs::remove_dir_all(parent).unwrap();
        std::fs::remove_dir_all(target).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn worker_directory_creation_rejects_a_link_at_a_fixed_child() {
        use std::os::unix::fs::symlink;

        let principal = resolve_current_worker_principal().unwrap();
        let parent = unique_test_directory("child-symlink");
        let root = parent.join("chosen-root");
        let target = unique_test_directory("child-symlink-target");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir(&target).unwrap();
        symlink(&target, root.join("repos")).unwrap();
        let layout =
            resolve_worker_directory_layout(InstallationScope::System, &principal, Some(&root))
                .unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(directory_entry_names(&target).is_empty());
        assert_eq!(
            directory_entry_names(&root),
            BTreeSet::from(["repos".to_owned()])
        );
        std::fs::remove_file(root.join("repos")).unwrap();
        std::fs::remove_dir_all(parent).unwrap();
        std::fs::remove_dir_all(target).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn new_worker_directories_are_mode_0700_even_with_a_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;

        if let Some(root) = std::env::var_os(MODE_CHILD_ROOT_ENV) {
            let principal = resolve_current_worker_principal().unwrap();
            let layout = resolve_worker_directory_layout(
                InstallationScope::System,
                &principal,
                Some(Path::new(&root)),
            )
            .unwrap();
            let previous = unsafe { libc::umask(0) };
            let result = create_worker_directory_layout(&layout);
            unsafe { libc::umask(previous) };
            result.unwrap();
            return;
        }

        let parent = unique_test_directory("restrictive-mode");
        std::fs::create_dir(&parent).unwrap();
        let root = parent.join("chosen-root");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "platform::worker_directory_tests::new_worker_directories_are_mode_0700_even_with_a_permissive_umask",
            ])
            .env(MODE_CHILD_ROOT_ENV, &root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        for path in std::iter::once(root.as_path()).chain(
            WorkerDirectoryLayout::child_names()
                .into_iter()
                .map(|name| root.join(name))
                .collect::<Vec<_>>()
                .iter()
                .map(PathBuf::as_path),
        ) {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700,
                "{path:?}"
            );
        }
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn fresh_native_profile_materializes_only_the_missing_standard_base_and_layout() {
        use std::os::unix::fs::PermissionsExt;

        let parent = unique_test_directory("fresh-profile");
        let profile = parent.join("profile");
        std::fs::create_dir_all(&profile).unwrap();
        let root = profile.join("new/data/base/styrn");
        let principal = resolve_current_worker_principal().unwrap();
        let layout = WorkerDirectoryLayout::new(
            InstallationScope::User,
            root.clone(),
            WorkerRootCreationPolicy::CreateMissingFrom(profile.clone()),
            principal,
        );

        create_worker_directory_layout(&layout)
            .unwrap()
            .bind_after_reverify(|_| Ok::<_, ()>(()))
            .unwrap();

        assert_eq!(
            directory_entry_names(&profile),
            BTreeSet::from(["new".to_owned()])
        );
        for path in [
            profile.join("new"),
            profile.join("new/data"),
            profile.join("new/data/base"),
            root.clone(),
        ] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert_eq!(directory_entry_names(&root).len(), 5);

        std::fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn user_profile_anchor_rejects_unrelated_mutation_before_creating_a_base() {
        use std::os::unix::fs::PermissionsExt;

        let principal = resolve_current_worker_principal().unwrap();
        let parent = unique_test_directory("mutable-profile-anchor");
        let profile = parent.join("profile");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o777)).unwrap();
        let root = profile.join("new/data/styrn");
        let layout = WorkerDirectoryLayout::new(
            InstallationScope::User,
            root.clone(),
            WorkerRootCreationPolicy::CreateMissingFrom(profile.clone()),
            principal,
        );

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!profile.join("new").exists());
        assert_eq!(
            std::fs::metadata(&profile).unwrap().permissions().mode() & 0o777,
            0o777
        );
        std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn override_parent_must_exist_and_is_never_materialized() {
        let principal = resolve_current_worker_principal().unwrap();
        let parent = unique_test_directory("missing-override-parent");
        std::fs::create_dir(&parent).unwrap();
        let missing_parent = parent.join("must-not-be-created");
        let root = missing_parent.join("chosen-root");
        let layout =
            resolve_worker_directory_layout(InstallationScope::System, &principal, Some(&root))
                .unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(!missing_parent.exists());
        assert!(directory_entry_names(&parent).is_empty());
        std::fs::remove_dir(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn system_override_rejects_an_untrusted_writable_parent_before_any_creation() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let principal = resolve_current_worker_principal().unwrap();
        let parent = unique_test_directory("writable-override-parent");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        let before = std::fs::metadata(&parent).unwrap();
        let root = parent.join("chosen-root");
        let layout =
            resolve_worker_directory_layout(InstallationScope::System, &principal, Some(&root))
                .unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(directory_entry_names(&parent).is_empty());
        let after = std::fs::metadata(&parent).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(before.mode(), after.mode());
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir(parent).unwrap();
    }

    #[test]
    fn unrelated_preexisting_root_entry_is_preserved_and_not_claimed() {
        let principal = resolve_current_worker_principal().unwrap();
        let parent = unique_test_directory("unrelated-root-entry");
        let root = parent.join("chosen-root");
        std::fs::create_dir(&parent).unwrap();
        let layout =
            resolve_worker_directory_layout(InstallationScope::System, &principal, Some(&root))
                .unwrap();
        create_worker_directory_layout(&layout)
            .unwrap()
            .bind_after_reverify(|_| Ok::<_, ()>(()))
            .unwrap();
        let unrelated = root.join("operator-notes.txt");
        std::fs::write(&unrelated, b"leave this entry alone\n").unwrap();
        let before = std::fs::metadata(&unrelated).unwrap();
        create_worker_directory_layout(&layout).unwrap();

        assert_eq!(
            std::fs::read(&unrelated).unwrap(),
            b"leave this entry alone\n"
        );
        let after = std::fs::metadata(&unrelated).unwrap();
        assert_eq!(before.len(), after.len());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
            assert_eq!(before.mode(), after.mode());
            assert_eq!(before.uid(), after.uid());
            assert_eq!(before.gid(), after.gid());
        }

        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn concurrent_creators_converge_on_one_stable_fixed_layout() {
        if let Some(root) = std::env::var_os(CONCURRENT_CHILD_ROOT_ENV) {
            let principal = resolve_current_worker_principal().unwrap();
            let layout = resolve_worker_directory_layout(
                InstallationScope::System,
                &principal,
                Some(Path::new(&root)),
            )
            .unwrap();
            create_worker_directory_layout(&layout)
                .unwrap()
                .bind_after_reverify(|_| Ok::<_, ()>(()))
                .unwrap();
            return;
        }

        let parent = unique_test_directory("concurrent-creators");
        std::fs::create_dir(&parent).unwrap();
        let root = parent.join("chosen-root");
        let children = (0..4)
            .map(|_| {
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "platform::worker_directory_tests::concurrent_creators_converge_on_one_stable_fixed_layout",
                    ])
                    .env(CONCURRENT_CHILD_ROOT_ENV, &root)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        for child in children {
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert_eq!(
            directory_entry_names(&root),
            BTreeSet::from([
                "artifacts".to_owned(),
                "cache".to_owned(),
                "jobs".to_owned(),
                "logs".to_owned(),
                "repos".to_owned(),
            ])
        );
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn absolute_xdg_data_home_is_a_separate_materializable_user_base() {
        if let Some(expected) = std::env::var_os(XDG_CHILD_ROOT_ENV) {
            let principal = resolve_current_worker_principal().unwrap();
            let layout =
                resolve_worker_directory_layout(InstallationScope::User, &principal, None).unwrap();
            assert_eq!(layout.root(), Path::new(&expected));
            create_worker_directory_layout(&layout).unwrap();
            return;
        }

        let parent = unique_test_directory("xdg-base");
        std::fs::create_dir(&parent).unwrap();
        let data_home = parent.join("fresh/xdg/data");
        let root = data_home.join("styrn");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "platform::worker_directory_tests::absolute_xdg_data_home_is_a_separate_materializable_user_base",
            ])
            .env("XDG_DATA_HOME", &data_home)
            .env(XDG_CHILD_ROOT_ENV, &root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(directory_entry_names(&root).len(), 5);
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn absolute_xdg_data_home_with_trailing_slash_is_lexically_normalized() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        if let Some(expected) = std::env::var_os(XDG_CHILD_ROOT_ENV) {
            let principal = resolve_current_worker_principal().unwrap();
            let layout =
                resolve_worker_directory_layout(InstallationScope::User, &principal, None).unwrap();
            assert_eq!(layout.root(), Path::new(&expected));
            create_worker_directory_layout(&layout).unwrap();
            return;
        }

        let parent = unique_test_directory("xdg-base-trailing-slash");
        std::fs::create_dir(&parent).unwrap();
        let data_home = parent.join("fresh/xdg/data");
        let mut spelling = data_home.as_os_str().as_bytes().to_vec();
        spelling.push(b'/');
        let root = data_home.join("styrn");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "platform::worker_directory_tests::absolute_xdg_data_home_with_trailing_slash_is_lexically_normalized",
            ])
            .env("XDG_DATA_HOME", std::ffi::OsString::from_vec(spelling))
            .env(XDG_CHILD_ROOT_ENV, &root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(directory_entry_names(&root).len(), 5);
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "environmental: native Windows Developer Mode or SeCreateSymbolicLinkPrivilege"]
    fn native_windows_reparse_ancestor_is_rejected_without_touching_its_target() {
        use std::os::windows::fs::symlink_dir;

        let principal = resolve_current_worker_principal().unwrap();
        let parent = unique_test_directory("windows-reparse");
        let target = unique_test_directory("windows-reparse-target");
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&target).unwrap();
        symlink_dir(&target, parent.join("redirected-parent")).unwrap();
        let root = parent.join("redirected-parent/chosen-root");
        let layout =
            resolve_worker_directory_layout(InstallationScope::System, &principal, Some(&root))
                .unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(directory_entry_names(&target).is_empty());
        std::fs::remove_dir(parent.join("redirected-parent")).unwrap();
        std::fs::remove_dir_all(parent).unwrap();
        std::fs::remove_dir_all(target).unwrap();
    }

    #[cfg(unix)]
    fn native_profile_home_for_test() -> PathBuf {
        use std::os::unix::ffi::OsStringExt;

        let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_u8; 16 * 1024];
        let status = unsafe {
            libc::getpwuid_r(
                libc::getuid(),
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        assert_eq!(status, 0);
        assert!(!result.is_null());
        assert!(!entry.pw_dir.is_null());
        PathBuf::from(std::ffi::OsString::from_vec(
            unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) }
                .to_bytes()
                .to_vec(),
        ))
    }

    fn unique_test_directory(label: &str) -> PathBuf {
        #[cfg(unix)]
        let temporary = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        #[cfg(target_os = "windows")]
        let temporary = std::env::temp_dir();
        temporary.join(format!(
            "styrn-worker-layout-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ))
    }

    fn directory_entry_names(path: &Path) -> BTreeSet<String> {
        std::fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect()
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ManifestOwner {
    System,
    #[allow(dead_code)] // Source-including manifest fixtures omit the user receipt store.
    User,
    #[cfg(test)]
    CurrentProcess,
    #[cfg(test)]
    CurrentProcessWorker,
}

#[cfg(unix)]
fn private_file_parent_mode_is_valid(owner: ManifestOwner, mode: u32) -> bool {
    match owner {
        ManifestOwner::User => mode & 0o777 == 0o700,
        ManifestOwner::System => mode & 0o022 == 0,
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => mode & 0o022 == 0,
    }
}

/// A staging pathname created with the platform's private-at-creation policy.
///
/// The containing parent is verified against worker takeover before this value
/// is minted, so keeping its field private prevents generic code from
/// publishing a separately created or worker-authorized directory.
pub(crate) struct PrivateManifestStagingDirectory {
    path: PathBuf,
}

/// A private, same-directory publication temporary whose identity was captured
/// from the handle returned by the exclusive create operation.
#[allow(dead_code)] // Consumed by the T0.13 receipt durability follow-up.
pub(crate) struct PrivatePublicationFile {
    path: PathBuf,
    file: std::fs::File,
    identity: PrivateFileIdentity,
    owner: ManifestOwner,
    principal: WorkerPrincipal,
}

#[allow(dead_code)] // Consumed by the T0.13 receipt durability follow-up.
pub(crate) struct CompletePrivatePublication(PrivatePublicationFile);

#[derive(Debug)]
#[allow(dead_code)] // Consumed by the T0.13 receipt durability follow-up.
pub(crate) struct DurablePrivatePublication {
    path: PathBuf,
    identity: PrivateFileIdentity,
}

impl std::fmt::Debug for PrivatePublicationFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivatePublicationFile")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for CompletePrivatePublication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("CompletePrivatePublication")
            .field(&self.0)
            .finish()
    }
}

impl std::io::Write for PrivatePublicationFile {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.file, bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.file)
    }
}

#[allow(dead_code)] // Consumed by the T0.13 receipt durability follow-up.
impl PrivatePublicationFile {
    pub(crate) fn complete_exact(
        mut self,
        expected_bytes: &[u8],
    ) -> std::io::Result<CompletePrivatePublication> {
        use std::io::{Read, Seek, Write};

        self.flush()?;
        self.file.sync_all()?;
        platform_impl::verify_private_file_handle_security(
            &self.file,
            self.owner,
            &self.principal,
        )?;
        if platform_impl::private_file_identity_from_handle(&self.file)? != self.identity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private publication handle identity changed",
            ));
        }
        let named = open_verified_private_file_for_read(
            &self.path,
            self.owner,
            &self.principal,
            self.identity,
        )?;
        drop(named);
        self.file.rewind()?;
        let mut actual = Vec::new();
        self.file.read_to_end(&mut actual)?;
        if actual != expected_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "private publication bytes differ from the completed document",
            ));
        }
        Ok(CompletePrivatePublication(self))
    }
}

#[allow(dead_code)] // Consumed by the T0.13 receipt durability follow-up.
impl CompletePrivatePublication {
    pub(crate) fn publish_no_replace(
        self,
        destination: &Path,
    ) -> std::io::Result<DurablePrivatePublication> {
        let temporary_parent = self
            .0
            .path
            .parent()
            .ok_or_else(|| std::io::Error::other("private publication has no parent"))?;
        if destination.parent() != Some(temporary_parent) || destination.file_name().is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "private publication destination must be a same-directory leaf",
            ));
        }
        platform_impl::publish_private_file_no_replace(
            &self.0.file,
            &self.0.path,
            destination,
            self.0.owner,
            &self.0.principal,
            self.0.identity,
        )?;
        Ok(DurablePrivatePublication {
            path: destination.to_path_buf(),
            identity: self.0.identity,
        })
    }
}

#[allow(dead_code)] // Consumed by the T0.13 receipt durability follow-up.
impl DurablePrivatePublication {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    #[allow(dead_code)] // Consumed by the T0.13 receipt integration follow-up.
    pub(crate) fn identity(&self) -> PrivateFileIdentity {
        self.identity
    }
}

/// Stable identity captured while enumerating a private transaction file.
/// The subsequent no-follow open must verify the same object before reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PrivateFileIdentity {
    first: u64,
    second: u64,
}

impl PrivateFileIdentity {
    fn new(first: u64, second: u64) -> Self {
        Self { first, second }
    }
}

impl PrivateManifestStagingDirectory {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

pub(crate) fn create_private_manifest_staging_directory(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> std::io::Result<PrivateManifestStagingDirectory> {
    platform_impl::create_private_manifest_staging_directory(path, owner, principal)?;
    Ok(PrivateManifestStagingDirectory {
        path: path.to_path_buf(),
    })
}

pub(crate) fn harden_manifest_directory(
    path: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
) -> std::io::Result<()> {
    platform_impl::harden_manifest_directory(path, owner, worker)
}

pub(crate) fn harden_manifest_file(
    path: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
) -> std::io::Result<()> {
    platform_impl::harden_manifest_file(path, owner, worker)
}

pub(crate) fn open_manifest_lock(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> std::io::Result<std::fs::File> {
    platform_impl::open_manifest_lock(path, owner, principal)
}

#[allow(dead_code)] // Source-including manifest tests do not include receipt recovery.
pub(crate) fn verify_private_file_security(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> std::io::Result<()> {
    platform_impl::verify_private_file_security(path, owner, principal)
}

pub(crate) fn create_private_file(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> std::io::Result<std::fs::File> {
    platform_impl::create_private_file(path, owner, principal)
}

#[allow(dead_code)] // Consumed by the T0.13 receipt durability follow-up.
pub(crate) fn create_private_publication_file(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> std::io::Result<PrivatePublicationFile> {
    if path.parent().is_none() || path.file_name().is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private publication temporary must have a parent and leaf name",
        ));
    }
    let file = platform_impl::create_private_file(path, owner, principal)?;
    let identity = platform_impl::private_file_identity_from_handle(&file)?;
    platform_impl::verify_private_file_handle_security(&file, owner, principal)?;
    Ok(PrivatePublicationFile {
        path: path.to_path_buf(),
        file,
        identity,
        owner,
        principal: principal.clone(),
    })
}

#[allow(dead_code)] // Source-including manifest tests omit receipt recovery.
pub(crate) fn private_file_identity(path: &Path) -> std::io::Result<PrivateFileIdentity> {
    platform_impl::private_file_identity(path)
}

#[allow(dead_code)] // Source-including manifest tests omit receipt recovery.
pub(crate) fn open_verified_private_file_for_read(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    expected_identity: PrivateFileIdentity,
) -> std::io::Result<std::fs::File> {
    platform_impl::open_verified_private_file_for_read(path, owner, principal, expected_identity)
}

#[allow(dead_code)] // Source-including manifest tests omit authorization execution.
pub(crate) struct PrivateFileRemoval(platform_impl::PrivateFileRemoval);

#[allow(dead_code)] // Source-including manifest tests omit authorization execution.
pub(crate) fn prepare_verified_private_file_removal(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    expected_identity: PrivateFileIdentity,
) -> std::io::Result<PrivateFileRemoval> {
    platform_impl::prepare_verified_private_file_removal(path, owner, principal, expected_identity)
        .map(PrivateFileRemoval)
}

#[allow(dead_code)] // Source-including manifest tests omit authorization execution.
pub(crate) fn consume_verified_private_file(removal: PrivateFileRemoval) -> std::io::Result<()> {
    platform_impl::consume_verified_private_file(removal.0)
}

pub(crate) fn verify_manifest_security(
    path: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
    trusted_root: &Path,
) -> std::io::Result<()> {
    platform_impl::verify_manifest_security(path, owner, worker, trusted_root)
}

#[allow(dead_code)] // Source-including manifest tests do not include receipt reads.
pub(crate) fn open_verified_manifest_file_for_read(
    path: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
    trusted_root: &Path,
) -> std::io::Result<std::fs::File> {
    platform_impl::open_verified_manifest_file_for_read(path, owner, worker, trusted_root)
}

pub(crate) fn verify_manifest_ancestors(
    directory: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
    trusted_root: &Path,
) -> std::io::Result<()> {
    platform_impl::verify_manifest_ancestors(directory, owner, worker, trusted_root)
}

pub(crate) fn verify_manifest_parent_chain(
    parent: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
) -> std::io::Result<()> {
    platform_impl::verify_manifest_parent_chain(parent, owner, worker)
}

pub(crate) fn verify_manifest_directory_security(
    directory: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
) -> std::io::Result<()> {
    platform_impl::verify_manifest_directory_security(directory, owner, worker)
}

pub(crate) fn publish_manifest_directory(
    staging: &PrivateManifestStagingDirectory,
    destination: &Path,
) -> std::io::Result<()> {
    platform_impl::publish_manifest_directory(staging.path(), destination)
}

pub(crate) fn verify_manifest_file_target(path: &Path) -> std::io::Result<()> {
    platform_impl::verify_manifest_file_target(path)
}

pub(crate) fn resolve_current_worker_principal() -> std::io::Result<WorkerPrincipal> {
    platform_impl::resolve_current_worker_principal()
}

#[allow(dead_code)] // Explicit system-account selection is exercised by environmental gates.
pub(crate) fn resolve_named_worker_principal(
    name: &str,
    account_policy: WorkerAccountPolicy,
) -> std::io::Result<WorkerPrincipal> {
    platform_impl::resolve_named_worker_principal(name, account_policy)
}

pub(crate) fn verify_worker_principal(principal: &WorkerPrincipal) -> std::io::Result<()> {
    platform_impl::verify_worker_principal(principal)
}

/// Replaces a completed temporary file with its destination. Ownership and
/// permission hardening belong at this boundary in T0.7.
pub(crate) fn replace_file(temporary: &Path, destination: &Path) -> std::io::Result<()> {
    #[cfg(not(target_os = "windows"))]
    {
        std::fs::rename(temporary, destination)
    }
    #[cfg(target_os = "windows")]
    {
        windows::replace_file(temporary, destination)
    }
}

/// Makes a completed atomic directory-entry replacement durable where the
/// host requires an explicit parent-directory flush. Windows publication uses
/// `MOVEFILE_WRITE_THROUGH` in `replace_file`.
#[allow(dead_code)] // Source-including contract tests do not include receipt publication.
pub(crate) fn sync_parent_directory(directory: &Path) -> std::io::Result<()> {
    #[cfg(not(target_os = "windows"))]
    {
        std::fs::File::open(directory)?.sync_all()
    }
    #[cfg(target_os = "windows")]
    {
        let _ = directory;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
use linux as platform_impl;

#[cfg(target_os = "macos")]
use macos as platform_impl;

#[cfg(target_os = "windows")]
use windows as platform_impl;
