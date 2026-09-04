use super::{
    ManifestOwner, PrincipalKind, PrivateFileIdentity, SetupExecutionContext, SetupHostPrivilege,
    UnixCallerIds, WorkerAccountPolicy, WorkerPrincipal,
};
use std::ffi::{CString, OsString};
use std::fs;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

pub(super) fn baseline_probe_snapshot(
    kind: super::BaselineProbeKind,
    authorized_public_keys: &[String],
    tailscale_mode: &str,
) -> super::BaselineProbeSnapshot {
    match kind {
        super::BaselineProbeKind::SshServer => ssh_server_snapshot(authorized_public_keys),
        super::BaselineProbeKind::Tailscale => tailscale_snapshot(tailscale_mode),
        super::BaselineProbeKind::Git => git_snapshot(),
        super::BaselineProbeKind::SleepPolicy => sleep_snapshot(),
        super::BaselineProbeKind::Styrnd | super::BaselineProbeKind::Deferred => {
            super::BaselineProbeSnapshot::Unknowable
        }
    }
}

fn ssh_server_snapshot(required: &[String]) -> super::BaselineProbeSnapshot {
    let Some(sshd) = [
        Path::new("/usr/sbin/sshd"),
        Path::new("/usr/local/sbin/sshd"),
    ]
    .into_iter()
    .find(|path| path.is_file()) else {
        return super::BaselineProbeSnapshot::Absent;
    };
    let service_observations = ["sshd.service", "ssh.service"].map(|service| {
        super::run_fixed_baseline_command(
            Path::new("/usr/bin/systemctl"),
            &["is-active", "--quiet", service],
        )
    });
    let service_running = if service_observations
        .iter()
        .any(|result| result.as_ref().is_ok_and(|output| output.success))
    {
        true
    } else if service_observations.iter().any(Result::is_ok) {
        false
    } else {
        return super::BaselineProbeSnapshot::Unknowable;
    };
    let account = match account_details_for_uid(
        unsafe { libc::getuid() },
        WorkerAccountPolicy::CurrentUser,
    ) {
        Ok(account) => account,
        Err(_) => return super::BaselineProbeSnapshot::Unknowable,
    };
    let match_context = format!(
        "user={},host=localhost,addr=127.0.0.1",
        account.principal.name()
    );
    let config = match super::run_fixed_baseline_command(sshd, &["-T", "-C", &match_context]) {
        Ok(output) if output.success => super::parse_effective_sshd_config(&output.stdout),
        Ok(_) | Err(_) => return super::BaselineProbeSnapshot::Unknowable,
    };
    let Some(config) = config else {
        return super::BaselineProbeSnapshot::Unknowable;
    };
    let home = PathBuf::from(account.home);
    super::BaselineProbeSnapshot::Present {
        version: None,
        healthy: service_running
            && config.public_key_authentication()
            && authorized_keys_are_ready(
                &home,
                unsafe { libc::getuid() },
                config.authorized_keys_files(),
                required,
            ),
    }
}

fn tailscale_snapshot(requested_mode: &str) -> super::BaselineProbeSnapshot {
    let Some(program) = [
        Path::new("/usr/bin/tailscale"),
        Path::new("/usr/local/bin/tailscale"),
    ]
    .into_iter()
    .find(|path| path.is_file()) else {
        return super::BaselineProbeSnapshot::Absent;
    };
    let service_active = super::run_fixed_baseline_command(
        Path::new("/usr/bin/systemctl"),
        &["is-active", "--quiet", "tailscaled.service"],
    )
    .is_ok_and(|output| output.success);
    let service_enabled = super::run_fixed_baseline_command(
        Path::new("/usr/bin/systemctl"),
        &["is-enabled", "--quiet", "tailscaled.service"],
    )
    .is_ok_and(|output| output.success);
    match super::run_fixed_baseline_command(program, &["status", "--json"]) {
        Ok(output) if output.success => parse_tailscale_status(
            &output.stdout,
            service_active && service_enabled,
            requested_mode,
        )
        .unwrap_or(super::BaselineProbeSnapshot::Unknowable),
        Ok(_) => super::BaselineProbeSnapshot::Unknowable,
        Err(_) => super::BaselineProbeSnapshot::Unknowable,
    }
}

fn git_snapshot() -> super::BaselineProbeSnapshot {
    let Some(program) = [Path::new("/usr/bin/git"), Path::new("/usr/local/bin/git")]
        .into_iter()
        .find(|path| path.is_file())
    else {
        return super::BaselineProbeSnapshot::Absent;
    };
    match super::run_fixed_baseline_command(program, &["--version"]) {
        Ok(output) if output.success => parse_git_version(&output.stdout)
            .map(|version| super::BaselineProbeSnapshot::Present {
                version: Some(version),
                healthy: true,
            })
            .unwrap_or(super::BaselineProbeSnapshot::Unknowable),
        Ok(_) => super::BaselineProbeSnapshot::Broken,
        Err(_) => super::BaselineProbeSnapshot::Unknowable,
    }
}

fn sleep_snapshot() -> super::BaselineProbeSnapshot {
    let arguments = [
        "is-enabled",
        "sleep.target",
        "suspend.target",
        "hibernate.target",
        "hybrid-sleep.target",
    ];
    match super::run_fixed_baseline_command(Path::new("/usr/bin/systemctl"), &arguments) {
        Ok(output) => parse_sleep_posture(&output.stdout)
            .map(|healthy| super::BaselineProbeSnapshot::Present {
                version: None,
                healthy,
            })
            .unwrap_or(super::BaselineProbeSnapshot::Unknowable),
        Err(_) => super::BaselineProbeSnapshot::Unknowable,
    }
}

fn parse_git_version(bytes: &[u8]) -> Option<String> {
    if bytes.len() > 256 {
        return None;
    }
    let version = std::str::from_utf8(bytes)
        .ok()?
        .trim()
        .strip_prefix("git version ")?;
    (!version.is_empty()
        && version.len() <= 96
        && version.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'(' | b')')
        }))
    .then(|| version.to_owned())
}

fn parse_tailscale_status(
    bytes: &[u8],
    persistent: bool,
    requested_mode: &str,
) -> Option<super::BaselineProbeSnapshot> {
    super::tailscale_status_snapshot(
        bytes,
        super::BaselineTailscaleMode::Tailscaled,
        persistent,
        true,
        requested_mode,
        super::BaselineTailscaleMode::Tailscaled,
    )
}

fn parse_sleep_posture(bytes: &[u8]) -> Option<bool> {
    let output = std::str::from_utf8(bytes).ok()?;
    let states = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if states.len() != 4
        || states.iter().any(|state| {
            !matches!(
                *state,
                "masked" | "enabled" | "disabled" | "static" | "indirect" | "generated"
            )
        })
    {
        return None;
    }
    Some(states.iter().all(|state| *state == "masked"))
}

fn authorized_keys_are_ready(
    home: &Path,
    uid: u32,
    configured: &[String],
    required: &[String],
) -> bool {
    let Ok(home_metadata) = fs::symlink_metadata(home) else {
        return false;
    };
    if !secure_ssh_path_metadata(&home_metadata, uid, true) {
        return false;
    }
    let ssh = home.join(".ssh");
    let Ok(metadata) = fs::symlink_metadata(&ssh) else {
        return false;
    };
    if !secure_ssh_path_metadata(&metadata, uid, true) {
        return false;
    }
    configured.iter().any(|configured| {
        let Some(path) = canonical_authorized_keys_path(home, configured) else {
            return false;
        };
        authorized_keys_file_is_ready(&path, uid, required)
    })
}

fn canonical_authorized_keys_path(home: &Path, configured: &str) -> Option<PathBuf> {
    let relative = configured
        .strip_prefix("%h/")
        .or_else(|| configured.strip_prefix("./"))
        .unwrap_or(configured);
    if !matches!(relative, ".ssh/authorized_keys" | ".ssh/authorized_keys2") {
        return None;
    }
    Some(home.join(relative))
}

fn authorized_keys_file_is_ready(path: &Path, uid: u32, required: &[String]) -> bool {
    let Ok(mut file) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    else {
        return false;
    };
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if !secure_ssh_path_metadata(&metadata, uid, false) || metadata.len() > 1024 * 1024 {
        return false;
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    if std::io::Read::by_ref(&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > 1024 * 1024
    {
        return false;
    }
    let Ok(contents) = std::str::from_utf8(&bytes) else {
        return false;
    };
    let keys = contents
        .lines()
        .map(str::trim)
        .filter_map(super::parse_authorized_key_line)
        .collect::<Vec<_>>();
    if required.is_empty() {
        !keys.is_empty()
    } else {
        required.iter().all(|required| {
            super::parse_authorized_key_line(required)
                .is_some_and(|required| keys.contains(&required))
        })
    }
}

fn secure_ssh_path_metadata(metadata: &fs::Metadata, uid: u32, directory: bool) -> bool {
    !metadata.file_type().is_symlink()
        && if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        }
        && matches!(metadata.uid(), owner if owner == uid || owner == 0)
        && metadata.mode() & 0o022 == 0
}

#[cfg(test)]
mod baseline_probe_tests {
    use super::super::{BaselineProbeKind, BaselineProbeSnapshot};

    #[test]
    #[ignore = "requires a disposable Linux user with running sshd and Tailscale, valid per-user authorized_keys, Git, and all sleep targets masked"]
    fn native_rootless_baseline_positive_requires_disposable_configured_host() {
        for kind in [
            BaselineProbeKind::SshServer,
            BaselineProbeKind::Tailscale,
            BaselineProbeKind::Git,
            BaselineProbeKind::SleepPolicy,
        ] {
            assert!(matches!(
                super::baseline_probe_snapshot(kind, &[], ""),
                BaselineProbeSnapshot::Present { healthy: true, .. }
                    | BaselineProbeSnapshot::TailscalePresent { healthy: true, .. }
            ));
        }
    }

    #[test]
    #[ignore = "requires a disposable Linux user with deliberately denied, malformed, and timeout-injected native probe state"]
    fn native_rootless_baseline_negative_requires_disposable_faulted_host() {
        assert!(matches!(
            super::baseline_probe_snapshot(BaselineProbeKind::SleepPolicy, &[], ""),
            BaselineProbeSnapshot::Unknowable
        ));
    }
}

#[cfg(test)]
type PostWorkerMkdirHook = fn(i32, &std::ffi::CStr);

#[derive(Clone, Copy, Eq, PartialEq)]
enum WorkerPublicationInterruption {
    AfterProvenance,
    AfterRootOwnership,
}

#[cfg(test)]
thread_local! {
    static POST_WORKER_MKDIR_HOOK: std::cell::Cell<Option<PostWorkerMkdirHook>> = const {
        std::cell::Cell::new(None)
    };
    static WORKER_MKDIR_INTERRUPT_AFTER: std::cell::Cell<Option<usize>> = const {
        std::cell::Cell::new(None)
    };
    static WORKER_PUBLICATION_INTERRUPT: std::cell::Cell<Option<WorkerPublicationInterruption>> = const {
        std::cell::Cell::new(None)
    };
    static WORKER_RECOVERY_IDENTITY_OVERRIDE: std::cell::RefCell<Option<(Vec<u8>, super::WorkerDirectoryIdentity)>> =
        const { std::cell::RefCell::new(None) };
    static WORKER_NODE_POST_PUBLISH_FAILURE: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static WORKER_NODE_POST_PUBLISH_FAULT: std::cell::Cell<Option<super::WorkerNodePostPublishFault>> = const {
        std::cell::Cell::new(None)
    };
    static WORKER_NODE_PRINCIPAL_DRIFT: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static WORKER_PROVENANCE_RETIREMENT_FAULT: std::cell::Cell<Option<super::WorkerProvenanceRetirementFault>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
fn set_post_worker_mkdir_hook(hook: PostWorkerMkdirHook) {
    POST_WORKER_MKDIR_HOOK.with(|slot| slot.set(Some(hook)));
}

#[cfg(test)]
fn set_worker_mkdir_interrupt_after(remaining: Option<usize>) {
    WORKER_MKDIR_INTERRUPT_AFTER.with(|slot| slot.set(remaining));
}

#[cfg(test)]
fn set_worker_publication_interrupt(interruption: Option<WorkerPublicationInterruption>) {
    WORKER_PUBLICATION_INTERRUPT.with(|slot| slot.set(interruption));
}

#[cfg(test)]
fn set_worker_recovery_identity_override(
    override_value: Option<(Vec<u8>, super::WorkerDirectoryIdentity)>,
) {
    WORKER_RECOVERY_IDENTITY_OVERRIDE.with(|slot| *slot.borrow_mut() = override_value);
}

#[cfg(test)]
pub(super) fn set_worker_node_post_publish_failure_for_test(fail: bool) {
    WORKER_NODE_POST_PUBLISH_FAILURE.with(|slot| slot.set(fail));
}

#[cfg(test)]
pub(super) fn set_worker_node_post_publish_fault_for_test(
    fault: Option<super::WorkerNodePostPublishFault>,
) {
    WORKER_NODE_POST_PUBLISH_FAULT.with(|slot| slot.set(fault));
}

#[cfg(test)]
pub(super) fn set_worker_node_principal_drift_for_test(drift: bool) {
    WORKER_NODE_PRINCIPAL_DRIFT.with(|slot| slot.set(drift));
}

#[cfg(test)]
pub(super) fn set_worker_provenance_retirement_fault_for_test(
    fault: Option<super::WorkerProvenanceRetirementFault>,
) {
    WORKER_PROVENANCE_RETIREMENT_FAULT.with(|slot| slot.set(fault));
}

#[cfg(test)]
fn fail_worker_provenance_retirement_at(
    phase: super::WorkerProvenanceRetirementFault,
) -> io::Result<()> {
    WORKER_PROVENANCE_RETIREMENT_FAULT.with(|slot| {
        if slot.get() == Some(phase) {
            slot.set(None);
            Err(io::Error::other(format!(
                "injected worker provenance retirement failure at {phase:?}"
            )))
        } else {
            Ok(())
        }
    })
}

#[cfg(test)]
fn fail_worker_node_post_publish_at(phase: super::WorkerNodePostPublishFault) -> io::Result<()> {
    WORKER_NODE_POST_PUBLISH_FAULT.with(|slot| {
        if slot.get() == Some(phase) {
            slot.set(None);
            Err(io::Error::other(format!(
                "injected worker node publication failure at {phase:?}"
            )))
        } else {
            Ok(())
        }
    })
}

fn worker_recovery_candidate_identity(
    _name: &[u8],
    directory: &std::fs::File,
) -> io::Result<super::WorkerDirectoryIdentity> {
    #[cfg(test)]
    if let Some((_, identity)) = WORKER_RECOVERY_IDENTITY_OVERRIDE.with(|slot| {
        slot.borrow()
            .as_ref()
            .filter(|(candidate, _)| candidate.as_slice() == _name)
            .cloned()
    }) {
        return Ok(identity);
    }
    worker_directory_identity(directory)
}

#[allow(dead_code)]
pub(crate) fn platform_name() -> &'static str {
    "linux"
}

pub(super) fn resolve_current_worker_principal() -> io::Result<WorkerPrincipal> {
    let real_uid = unsafe { libc::getuid() };
    let effective_uid = unsafe { libc::geteuid() };
    principal_for_uid(
        super::validate_unix_caller_ids(real_uid, effective_uid)?,
        WorkerAccountPolicy::CurrentUser,
    )
}

#[allow(dead_code)] // Consumed by the T0.14 setup action integration follow-up.
pub(super) fn default_worker_root(
    scope: super::InstallationScope,
    principal: &WorkerPrincipal,
) -> io::Result<(PathBuf, super::WorkerRootCreationPolicy)> {
    validate_worker_root_principal(scope, principal)?;
    match scope {
        super::InstallationScope::System => Ok((
            PathBuf::from("/srv/styrn"),
            super::WorkerRootCreationPolicy::ExistingParent {
                allow_untrusted_parent_create: false,
            },
        )),
        super::InstallationScope::User => {
            let current = resolve_current_worker_principal()?;
            super::validate_user_scope_principal(principal, &current)?;
            let account =
                account_details_for_uid(principal.unix_uid()?, principal.account_policy())?;
            let home = PathBuf::from(account.home);
            let (data_home, creation_policy) = match std::env::var_os("XDG_DATA_HOME") {
                Some(value) if Path::new(&value).is_absolute() => (
                    normalize_xdg_data_home(value),
                    super::WorkerRootCreationPolicy::CreateMissingFrom(PathBuf::from("/")),
                ),
                _ => (
                    home.join(".local/share"),
                    super::WorkerRootCreationPolicy::CreateMissingFrom(home),
                ),
            };
            if !worker_root_path_is_normalized(&data_home) {
                return Err(invalid_data(
                    "XDG_DATA_HOME is not a normalized absolute path",
                ));
            }
            Ok((data_home.join("styrn"), creation_policy))
        }
    }
}

fn normalize_xdg_data_home(value: OsString) -> PathBuf {
    let mut bytes = value.into_vec();
    while bytes.len() > 1 && bytes.last() == Some(&b'/') {
        bytes.pop();
    }
    PathBuf::from(OsString::from_vec(bytes))
}

#[allow(dead_code)] // Consumed by the T0.14 setup action integration follow-up.
pub(super) fn validate_worker_root_principal(
    scope: super::InstallationScope,
    principal: &WorkerPrincipal,
) -> io::Result<()> {
    verify_worker_principal(principal)?;
    if scope == super::InstallationScope::User {
        let current = resolve_current_worker_principal()?;
        super::validate_user_scope_principal(principal, &current)?;
    }
    Ok(())
}

fn revalidate_worker_root_principal(
    layout: &super::WorkerDirectoryLayout,
) -> io::Result<WorkerPrincipal> {
    #[cfg(test)]
    if WORKER_NODE_PRINCIPAL_DRIFT.with(std::cell::Cell::get) {
        return Err(permission_denied(
            "injected worker principal drift before retained binding",
        ));
    }
    #[cfg(test)]
    if let Some(revalidation) = &layout.principal_revalidation {
        let (resolved, current) = match revalidation {
            super::WorkerPrincipalRevalidationTest::Resolved { principal, current } => {
                (Ok(principal.clone()), current.as_ref())
            }
            super::WorkerPrincipalRevalidationTest::Deleted => (
                Err(io::Error::new(io::ErrorKind::NotFound, "worker deleted")),
                None,
            ),
        };
        return super::validate_revalidated_worker_principal(
            layout.scope,
            &layout.principal,
            resolved,
            current,
        );
    }
    let scope = layout.scope;
    let principal = &layout.principal;
    let resolved = principal_for_uid(principal.unix_uid()?, principal.account_policy());
    let current = if scope == super::InstallationScope::User {
        Some(resolve_current_worker_principal()?)
    } else {
        None
    };
    super::validate_revalidated_worker_principal(scope, principal, resolved, current.as_ref())
}

#[allow(dead_code)] // Consumed by the T0.14 setup action integration follow-up.
pub(super) fn worker_root_path_is_normalized(path: &Path) -> bool {
    let bytes = path.as_os_str().as_bytes();
    !bytes.contains(&0)
        && !bytes.ends_with(b"/")
        && !bytes.windows(2).any(|pair| pair == b"//")
        && !bytes
            .split(|byte| *byte == b'/')
            .any(|component| component == b"." || component == b"..")
}

#[allow(dead_code)] // Consumed by the T0.14 setup action integration follow-up.
pub(super) fn create_worker_directory_layout(
    layout: &super::WorkerDirectoryLayout,
) -> io::Result<super::WorkerDirectoryCreation> {
    let root_components = absolute_worker_components(layout.root())?;
    let expected_uid = layout.principal.unix_uid()?;
    let first_creatable = match &layout.creation_policy {
        super::WorkerRootCreationPolicy::ExistingParent { .. } => root_components
            .len()
            .checked_sub(1)
            .ok_or_else(|| invalid_data("worker root has no leaf component"))?,
        super::WorkerRootCreationPolicy::CreateMissingFrom(anchor) => {
            let anchor_components = absolute_worker_components(anchor)?;
            if !root_components.starts_with(&anchor_components)
                || root_components.len() == anchor_components.len()
            {
                return Err(permission_denied(
                    "worker standard root escapes its native profile anchor",
                ));
            }
            anchor_components.len()
        }
    };

    let mut directory = open_worker_filesystem_root()?;
    verify_worker_creation_ancestor(&directory, expected_uid)?;
    for component in &root_components[..first_creatable] {
        directory = open_worker_directory_at(&directory, component)?;
        verify_worker_creation_ancestor(&directory, expected_uid)?;
    }
    let creation_lock = directory;
    if unsafe { libc::flock(creation_lock.as_raw_fd(), libc::LOCK_EX) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let verified_principal = revalidate_worker_root_principal(layout)?;
    let expected_uid = verified_principal.unix_uid()?;
    let mut root_parent = creation_lock.try_clone()?;
    let mut creation_provenance = Vec::new();
    let mut pending_ownership = Vec::new();
    for component in &root_components[first_creatable..root_components.len() - 1] {
        let opened = open_or_create_worker_directory_at(
            &root_parent,
            &root_parent,
            component,
            true,
            expected_uid,
            false,
            None,
        )?;
        if let Some(provenance) = opened.provenance {
            creation_provenance.push(provenance);
        }
        if opened.disposition == super::WorkerDirectoryNodeDisposition::Created {
            pending_ownership.push((root_parent.try_clone()?, opened.directory.try_clone()?));
        }
        root_parent = opened.directory;
    }
    let root_name = root_components
        .last()
        .expect("the normalized worker root has a leaf component");
    let (root, staged_children) =
        create_or_open_complete_worker_root(&root_parent, root_name, expected_uid)?;
    let root_disposition = root.disposition;
    if let Some(provenance) = root.provenance {
        creation_provenance.push(provenance);
    }
    let directory = root.directory;
    let root_identity = worker_directory_identity(&directory)?;
    let root_observation = super::WorkerDirectoryNodeObservation::new(
        layout.root().to_path_buf(),
        root_disposition,
        root_identity,
    );

    let children = match staged_children {
        Some(children) => children,
        None => {
            open_or_create_worker_children(&root_parent, &directory, expected_uid, false, None)?
        }
    };

    for (parent, intermediate) in pending_ownership {
        harden_new_worker_directory(&intermediate, expected_uid)?;
        intermediate.sync_all()?;
        parent.sync_all()?;
    }
    if root_disposition == super::WorkerDirectoryNodeDisposition::Created {
        harden_new_worker_directory(&directory, expected_uid)?;
        directory.sync_all()?;
        root_parent.sync_all()?;
        maybe_interrupt_worker_publication(true, WorkerPublicationInterruption::AfterRootOwnership);
    }

    if worker_directory_identity(&directory)? != root_identity {
        return Err(permission_denied(
            "worker root identity changed during layout creation",
        ));
    }
    verify_worker_path_identity(layout.root(), root_identity)?;
    let mut child_observations = Vec::with_capacity(children.len());
    let mut child_handles = Vec::with_capacity(children.len());
    for (name, child) in super::WorkerDirectoryLayout::child_names()
        .into_iter()
        .zip(children)
    {
        let child = child.expect("every fixed worker child was opened or created");
        let reopened = open_worker_directory_at(&directory, name.as_bytes())?;
        let identity = worker_directory_identity(&child.directory)?;
        if worker_directory_identity(&reopened)? != identity {
            return Err(permission_denied(
                "worker layout child identity changed during creation",
            ));
        }
        child_observations.push(super::WorkerDirectoryNodeObservation::new(
            layout.root().join(name),
            child.disposition,
            identity,
        ));
        if let Some(provenance) = child.provenance {
            creation_provenance.push(provenance);
        }
        child_handles.push(child.directory);
    }
    let [repos, jobs, cache, artifacts, logs] = child_handles
        .try_into()
        .unwrap_or_else(|_| unreachable!("the worker layout always has exactly five children"));
    let lease = WorkerDirectoryLease {
        _creation_lock: creation_lock,
        layout: layout.clone(),
        nodes: [directory, repos, jobs, cache, artifacts, logs],
        creation_provenance,
    };
    Ok(super::WorkerDirectoryCreation::new(
        root_observation,
        child_observations
            .try_into()
            .unwrap_or_else(|_| unreachable!("the worker layout always has exactly five children")),
        lease,
    ))
}

pub(super) fn inspect_worker_directory_node(
    layout: &super::WorkerDirectoryLayout,
    node: super::WorkerDirectoryNode,
) -> super::WorkerDirectoryNodeInspection {
    let verified_principal = match revalidate_worker_root_principal(layout) {
        Ok(principal) => principal,
        Err(_) => {
            return super::WorkerDirectoryNodeInspection::Unknowable(
                super::WorkerDirectoryInspectionIssue::PrincipalDrift,
            );
        }
    };
    let Some(path) = layout.path_for_node(node) else {
        return super::WorkerDirectoryNodeInspection::Conflict(
            super::WorkerDirectoryInspectionIssue::UnsafeOrConflictingState,
        );
    };
    let expected_uid = match verified_principal.unix_uid() {
        Ok(uid) => uid,
        Err(_) => {
            return super::WorkerDirectoryNodeInspection::Unknowable(
                super::WorkerDirectoryInspectionIssue::PrincipalDrift,
            );
        }
    };
    match worker_node_has_reserved_evidence(layout, node, expected_uid) {
        Ok(true) => {
            return super::WorkerDirectoryNodeInspection::Conflict(
                super::WorkerDirectoryInspectionIssue::UnsafeOrConflictingState,
            );
        }
        Ok(false) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return super::WorkerDirectoryNodeInspection::Absent;
        }
        Err(error) => return classify_worker_directory_inspection_error(error),
    }
    let directory = match open_existing_worker_path(&path) {
        Ok(directory) => directory,
        Err(error) => return classify_worker_directory_inspection_error(error),
    };
    let verified = match node {
        super::WorkerDirectoryNode::Support { .. } => {
            verify_worker_creation_ancestor(&directory, expected_uid)
        }
        _ => verify_worker_directory_security(&directory, expected_uid),
    }
    .and_then(|()| {
        let identity = worker_directory_identity(&directory)?;
        verify_worker_path_identity(&path, identity)
    });
    match verified {
        Ok(()) => super::WorkerDirectoryNodeInspection::Healthy,
        Err(error) => classify_worker_directory_inspection_error(error),
    }
}

fn worker_node_has_reserved_evidence(
    layout: &super::WorkerDirectoryLayout,
    node: super::WorkerDirectoryNode,
    expected_uid: u32,
) -> io::Result<bool> {
    let root_components = absolute_worker_components(layout.root())?;
    let first_creatable = worker_first_creatable_component(layout, &root_components)?;
    let anchor = open_worker_creation_anchor(&root_components, first_creatable, expected_uid)?;
    let (staging_parent, destination_parent, name, _, _) = worker_node_location(
        layout,
        node,
        &anchor,
        &root_components,
        first_creatable,
        expected_uid,
    )?;
    let staging = worker_staging_name(&destination_parent, name)?;
    let provenance = worker_creation_provenance_name(&destination_parent, name)?;
    if worker_parent_entry_exists(&staging_parent, &staging)?
        || worker_parent_entry_exists(&staging_parent, &provenance)?
    {
        return Ok(true);
    }
    let retired = worker_creation_retired_provenance_name(&destination_parent, name)?;
    if !worker_parent_entry_exists(&staging_parent, &retired)? {
        return Ok(false);
    }
    let directory = open_worker_directory_at(&destination_parent, name).map_err(|_| {
        permission_denied("retired worker provenance has no exact destination directory")
    })?;
    let identity = worker_recovery_candidate_identity(name, &directory)?;
    open_retired_worker_creation_provenance(
        &staging_parent,
        &destination_parent,
        name,
        identity,
        expected_uid,
    )?
    .ok_or_else(|| permission_denied("retired worker provenance marker disappeared"))?;
    Ok(false)
}

fn worker_parent_entry_exists(parent: &std::fs::File, name: &std::ffi::CStr) -> io::Result<bool> {
    let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut status,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(error)
    }
}

fn classify_worker_directory_inspection_error(
    error: io::Error,
) -> super::WorkerDirectoryNodeInspection {
    if error.kind() == io::ErrorKind::NotFound {
        super::WorkerDirectoryNodeInspection::Absent
    } else if error.kind() == io::ErrorKind::PermissionDenied && error.raw_os_error().is_none() {
        super::WorkerDirectoryNodeInspection::Conflict(
            super::WorkerDirectoryInspectionIssue::UnsafeOrConflictingState,
        )
    } else {
        super::WorkerDirectoryNodeInspection::Unknowable(
            super::WorkerDirectoryInspectionIssue::ObservationUnavailable,
        )
    }
}

pub(super) fn create_worker_directory_node(
    layout: &super::WorkerDirectoryLayout,
    node: super::WorkerDirectoryNode,
) -> Result<super::WorkerDirectoryNodeCreateOutcome, super::WorkerDirectoryNodeCreationError> {
    let (
        creation_lock,
        lock_anchor_path,
        lock_anchor_identity,
        parent,
        destination_parent,
        destination_name,
        path,
        expected_uid,
        opened,
    ) = (|| -> Result<_, super::WorkerDirectoryNodeCreationError> {
        let root_components = absolute_worker_components(layout.root())?;
        let first_creatable = worker_first_creatable_component(layout, &root_components)?;
        let lock_anchor_path = worker_creation_anchor_path(layout)?;
        let initial_uid = layout.principal.unix_uid()?;
        let creation_lock =
            open_worker_creation_anchor(&root_components, first_creatable, initial_uid)?;
        let lock_anchor_identity = worker_directory_identity(&creation_lock)?;
        #[cfg(test)]
        probe_worker_layout_lock_contention_for_action_test(&creation_lock)?;
        if unsafe { libc::flock(creation_lock.as_raw_fd(), libc::LOCK_EX) } == -1 {
            return Err(io::Error::last_os_error().into());
        }
        #[cfg(test)]
        super::notify_worker_layout_lock_probe_for_action_test(
            super::WorkerLayoutLockProbeEvent::Acquired,
        );
        verify_worker_path_identity(&lock_anchor_path, lock_anchor_identity)?;
        let expected_uid = revalidate_worker_root_principal(layout)?.unix_uid()?;
        let (staging_parent, parent, name, path, canonical) = worker_node_location(
            layout,
            node,
            &creation_lock,
            &root_components,
            first_creatable,
            expected_uid,
        )?;
        let destination_parent = parent.try_clone()?;
        let destination_name = CString::new(name)
            .map_err(|_| invalid_data("worker directory component contains a NUL byte"))?;
        let opened = match open_or_create_worker_directory_at(
            &staging_parent,
            &parent,
            destination_name.to_bytes(),
            true,
            expected_uid,
            canonical,
            None,
        ) {
            Ok(opened) => opened,
            Err(error) => {
                let (primary, published) = error.into_parts();
                let Some(opened) = published else {
                    return Err(primary.into());
                };
                let mut creation_provenance = Vec::new();
                if let Some(provenance) = opened.provenance {
                    creation_provenance.push(provenance);
                }
                let evidence = WorkerDirectoryNodeFailureEvidence {
                    lease: WorkerDirectoryNodeLease {
                        creation_lock,
                        lock_anchor_path,
                        lock_anchor_identity,
                        layout: layout.clone(),
                        node: opened.directory,
                        destination_parent,
                        destination_name,
                        path,
                        creation_provenance,
                    },
                };
                return Err(
                    super::WorkerDirectoryNodeCreationError::with_retained_evidence(
                        primary, evidence,
                    ),
                );
            }
        };
        Ok((
            creation_lock,
            lock_anchor_path,
            lock_anchor_identity,
            parent,
            destination_parent,
            destination_name,
            path,
            expected_uid,
            opened,
        ))
    })()?;
    if opened.disposition == super::WorkerDirectoryNodeDisposition::Existing {
        return Ok(super::WorkerDirectoryNodeCreateOutcome::Existing);
    }
    let mut creation_provenance = Vec::new();
    if let Some(provenance) = opened.provenance {
        creation_provenance.push(provenance);
    }
    let evidence = WorkerDirectoryNodeFailureEvidence {
        lease: WorkerDirectoryNodeLease {
            creation_lock,
            lock_anchor_path,
            lock_anchor_identity,
            layout: layout.clone(),
            node: opened.directory,
            destination_parent,
            destination_name,
            path,
            creation_provenance,
        },
    };
    let operation = (|| -> io::Result<super::WorkerDirectoryNodeObservation> {
        harden_new_worker_directory(&evidence.lease.node, expected_uid)?;
        evidence.lease.node.sync_all()?;
        parent.sync_all()?;
        let identity = worker_directory_identity(&evidence.lease.node)?;
        verify_worker_path_identity(&evidence.lease.path, identity)?;
        #[cfg(test)]
        if WORKER_NODE_POST_PUBLISH_FAILURE.with(std::cell::Cell::get) {
            return Err(io::Error::other(
                "injected worker node post-publication failure",
            ));
        }
        Ok(super::WorkerDirectoryNodeObservation::new(
            evidence.lease.path.clone(),
            super::WorkerDirectoryNodeDisposition::Created,
            identity,
        ))
    })();
    let observation = match operation {
        Ok(observation) => observation,
        Err(error) => {
            return Err(
                super::WorkerDirectoryNodeCreationError::with_retained_evidence(error, evidence),
            );
        }
    };
    Ok(super::WorkerDirectoryNodeCreateOutcome::Created(
        super::WorkerDirectoryNodeCreation::new(observation, evidence.lease),
    ))
}

#[cfg(test)]
fn probe_worker_layout_lock_contention_for_action_test(lock: &std::fs::File) -> io::Result<()> {
    if !super::worker_layout_lock_probe_is_enabled_for_action_test() {
        return Ok(());
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) } == -1 {
            return Err(io::Error::last_os_error());
        }
        super::notify_worker_layout_lock_probe_for_action_test(
            super::WorkerLayoutLockProbeEvent::UnexpectedlyAvailable,
        );
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error
        .raw_os_error()
        .is_some_and(|raw| raw == libc::EWOULDBLOCK || raw == libc::EAGAIN)
    {
        super::notify_worker_layout_lock_probe_for_action_test(
            super::WorkerLayoutLockProbeEvent::Contended,
        );
        Ok(())
    } else {
        Err(error)
    }
}

fn worker_node_location<'component>(
    layout: &super::WorkerDirectoryLayout,
    node: super::WorkerDirectoryNode,
    creation_lock: &std::fs::File,
    root_components: &[&'component [u8]],
    first_creatable: usize,
    expected_uid: u32,
) -> io::Result<(
    std::fs::File,
    std::fs::File,
    &'component [u8],
    PathBuf,
    bool,
)> {
    let root_index = root_components
        .len()
        .checked_sub(1)
        .ok_or_else(|| invalid_data("worker root has no leaf component"))?;
    let (target_index, child_name) = match node {
        super::WorkerDirectoryNode::Support { ordinal } => {
            let index = first_creatable
                .checked_add(usize::from(ordinal))
                .ok_or_else(|| invalid_data("worker support ordinal overflows"))?;
            if index >= root_index {
                return Err(permission_denied(
                    "worker support node is outside the closed materialization set",
                ));
            }
            (index, None)
        }
        super::WorkerDirectoryNode::Root => (root_index, None),
        super::WorkerDirectoryNode::Repos => (root_index, Some(b"repos".as_slice())),
        super::WorkerDirectoryNode::Jobs => (root_index, Some(b"jobs".as_slice())),
        super::WorkerDirectoryNode::Cache => (root_index, Some(b"cache".as_slice())),
        super::WorkerDirectoryNode::Artifacts => (root_index, Some(b"artifacts".as_slice())),
        super::WorkerDirectoryNode::Logs => (root_index, Some(b"logs".as_slice())),
    };
    let mut parent = creation_lock.try_clone()?;
    for component in &root_components[first_creatable..target_index] {
        parent = open_worker_directory_at(&parent, component)?;
        verify_worker_creation_ancestor(&parent, expected_uid)?;
    }
    if let Some(child_name) = child_name {
        let staging_parent = parent.try_clone()?;
        let root = open_worker_directory_at(&parent, root_components[root_index])?;
        verify_worker_directory_security(&root, expected_uid)?;
        return Ok((
            staging_parent,
            root,
            child_name,
            layout
                .path_for_node(node)
                .ok_or_else(|| invalid_data("worker node has no closed path"))?,
            true,
        ));
    }
    Ok((
        parent.try_clone()?,
        parent,
        root_components[target_index],
        layout
            .path_for_node(node)
            .ok_or_else(|| invalid_data("worker node has no closed path"))?,
        node == super::WorkerDirectoryNode::Root,
    ))
}

#[allow(dead_code)] // Retained by the T0.14 per-node Action receipt binder.
pub(super) struct WorkerDirectoryNodeLease {
    creation_lock: std::fs::File,
    lock_anchor_path: PathBuf,
    lock_anchor_identity: super::WorkerDirectoryIdentity,
    layout: super::WorkerDirectoryLayout,
    node: std::fs::File,
    destination_parent: std::fs::File,
    destination_name: CString,
    path: PathBuf,
    creation_provenance: Vec<WorkerCreationProvenance>,
}

#[allow(dead_code)] // Retained by the T0.14 per-node failure receipt binder.
pub(super) struct WorkerDirectoryNodeFailureEvidence {
    lease: WorkerDirectoryNodeLease,
}

#[allow(dead_code)] // Consumed by the T0.14 per-node failure receipt binder.
impl WorkerDirectoryNodeFailureEvidence {
    pub(super) const fn retained_count(&self) -> usize {
        1
    }
}

#[allow(dead_code)] // Consumed by the T0.14 per-node failure receipt binder.
pub(super) fn reverify_worker_directory_node_failure_evidence(
    evidence: &WorkerDirectoryNodeFailureEvidence,
) -> io::Result<super::WorkerDirectoryNodeObservation> {
    let identity = reverify_worker_directory_node_authority(&evidence.lease)?;
    Ok(super::WorkerDirectoryNodeObservation::new(
        evidence.lease.path.clone(),
        super::WorkerDirectoryNodeDisposition::Created,
        identity,
    ))
}

#[allow(dead_code)] // Consumed by the T0.14 per-node failure receipt binder.
pub(super) fn retire_worker_directory_node_failure_authority(
    evidence: &WorkerDirectoryNodeFailureEvidence,
) -> io::Result<()> {
    retire_worker_directory_node_authority(&evidence.lease)
}

#[allow(dead_code)] // Consumed by the T0.14 per-node Action receipt binder.
pub(super) fn reverify_worker_directory_node_lease(
    lease: &WorkerDirectoryNodeLease,
    observation: &super::WorkerDirectoryNodeObservation,
) -> io::Result<()> {
    let identity = reverify_worker_directory_node_authority(lease)?;
    if observation.path() != lease.path || identity != observation.identity() {
        return Err(permission_denied(
            "retained worker directory observation changed before release",
        ));
    }
    Ok(())
}

fn reverify_worker_directory_node_authority(
    lease: &WorkerDirectoryNodeLease,
) -> io::Result<super::WorkerDirectoryIdentity> {
    let principal = revalidate_worker_root_principal(&lease.layout)?;
    let expected_uid = principal.unix_uid()?;
    if worker_directory_identity(&lease.creation_lock)? != lease.lock_anchor_identity {
        return Err(permission_denied(
            "worker creation lock identity changed before retained evidence release",
        ));
    }
    verify_worker_path_identity(&lease.lock_anchor_path, lease.lock_anchor_identity)?;
    lease.node.sync_all()?;
    lease.destination_parent.sync_all()?;
    for provenance in &lease.creation_provenance {
        verify_worker_creation_provenance(provenance)?;
    }
    verify_worker_directory_security(&lease.node, expected_uid)?;
    let identity = worker_directory_identity(&lease.node)?;
    let relative =
        open_worker_directory_at(&lease.destination_parent, lease.destination_name.to_bytes())
            .map_err(|_| {
                permission_denied(
                    "worker directory descriptor-relative path changed before release",
                )
            })?;
    if worker_directory_identity(&relative)? != identity {
        return Err(permission_denied(
            "worker directory descriptor-relative path changed before release",
        ));
    }
    verify_worker_path_identity(&lease.path, identity)?;
    Ok(identity)
}

#[allow(dead_code)] // Consumed by the T0.14 per-node Action receipt binder.
pub(super) fn retire_worker_directory_node_authority(
    lease: &WorkerDirectoryNodeLease,
) -> io::Result<()> {
    for provenance in lease.creation_provenance.iter().rev() {
        retire_worker_creation_provenance(provenance)?;
    }
    Ok(())
}

pub(super) fn retire_succeeded_worker_directory_evidence(
    layout: &super::WorkerDirectoryLayout,
    node: super::WorkerDirectoryNode,
) -> io::Result<()> {
    let root_components = absolute_worker_components(layout.root())?;
    let first_creatable = match &layout.creation_policy {
        super::WorkerRootCreationPolicy::ExistingParent { .. } => root_components
            .len()
            .checked_sub(1)
            .ok_or_else(|| invalid_data("worker root has no leaf component"))?,
        super::WorkerRootCreationPolicy::CreateMissingFrom(anchor) => {
            let anchor_components = absolute_worker_components(anchor)?;
            if !root_components.starts_with(&anchor_components)
                || root_components.len() == anchor_components.len()
            {
                return Err(permission_denied(
                    "worker standard root escapes its native profile anchor",
                ));
            }
            anchor_components.len()
        }
    };
    let mut anchor = open_worker_filesystem_root()?;
    let initial_uid = layout.principal.unix_uid()?;
    verify_worker_creation_ancestor(&anchor, initial_uid)?;
    for component in &root_components[..first_creatable] {
        anchor = open_worker_directory_at(&anchor, component)?;
        verify_worker_creation_ancestor(&anchor, initial_uid)?;
    }
    if unsafe { libc::flock(anchor.as_raw_fd(), libc::LOCK_EX) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let expected_uid = revalidate_worker_root_principal(layout)?.unix_uid()?;
    let (staging_parent, destination_parent, name, path, canonical) = worker_node_location(
        layout,
        node,
        &anchor,
        &root_components,
        first_creatable,
        expected_uid,
    )?;
    let staging_name = worker_staging_name(&destination_parent, name)?;
    if worker_parent_entry_exists(&staging_parent, &staging_name)? {
        return Err(permission_denied(
            "succeeded worker evidence has an unresolved staging candidate",
        ));
    }
    let directory = open_worker_directory_at(&destination_parent, name)?;
    verify_existing_worker_directory(&directory, expected_uid, canonical)?;
    let identity = worker_directory_identity(&directory)?;
    verify_worker_path_identity(&path, identity)?;
    let retirement = open_worker_creation_provenance_for_retirement(
        &staging_parent,
        &destination_parent,
        name,
        identity,
        expected_uid,
    )?;
    retire_worker_creation_provenance_state(&retirement)
}

fn retire_worker_creation_provenance(provenance: &WorkerCreationProvenance) -> io::Result<()> {
    verify_worker_creation_provenance(provenance)?;
    let retired_name = worker_creation_retired_provenance_name_from_marker(&provenance.name)?;
    if worker_parent_entry_exists(&provenance.parent, &retired_name)? {
        return Err(permission_denied(
            "active and retired worker provenance markers both exist",
        ));
    }
    if unsafe {
        libc::renameat2(
            provenance.parent.as_raw_fd(),
            provenance.name.as_ptr(),
            provenance.parent.as_raw_fd(),
            retired_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } == -1
    {
        let error = io::Error::last_os_error();
        return Err(if error.kind() == io::ErrorKind::AlreadyExists {
            permission_denied("retired worker provenance marker already exists")
        } else {
            error
        });
    }
    #[cfg(test)]
    fail_worker_provenance_retirement_at(
        super::WorkerProvenanceRetirementFault::AfterMarkerRename,
    )?;
    // The exact retired directory is the durable terminal marker. A future
    // uninstall path may remove it; successful creation retirement must not.
    verify_retired_worker_creation_provenance(provenance)?;
    sync_worker_creation_provenance_parent(&provenance.parent)?;
    verify_retired_worker_creation_provenance(provenance)
}

enum WorkerCreationProvenanceRetirement {
    Active(WorkerCreationProvenance),
    Retired(WorkerCreationProvenance),
}

fn open_worker_creation_provenance_for_retirement(
    staging_parent: &std::fs::File,
    destination_parent: &std::fs::File,
    destination_name: &[u8],
    created_identity: super::WorkerDirectoryIdentity,
    expected_uid: u32,
) -> io::Result<WorkerCreationProvenanceRetirement> {
    let active_name = worker_creation_provenance_name(destination_parent, destination_name)?;
    let retired_name =
        worker_creation_retired_provenance_name(destination_parent, destination_name)?;
    let active_exists = worker_parent_entry_exists(staging_parent, &active_name)?;
    let retired_exists = worker_parent_entry_exists(staging_parent, &retired_name)?;
    if active_exists && retired_exists {
        return Err(permission_denied(
            "active and retired worker provenance markers both exist",
        ));
    }
    let (provenance, retired) = if active_exists {
        (
            open_worker_creation_provenance_at_name(
                staging_parent,
                destination_parent,
                destination_name,
                created_identity,
                expected_uid,
                active_name,
            )?
            .ok_or_else(|| permission_denied("active worker provenance marker disappeared"))?,
            false,
        )
    } else if retired_exists {
        (
            open_worker_creation_provenance_at_name(
                staging_parent,
                destination_parent,
                destination_name,
                created_identity,
                expected_uid,
                retired_name,
            )?
            .ok_or_else(|| permission_denied("retired worker provenance marker disappeared"))?,
            true,
        )
    } else {
        return Err(permission_denied(
            "succeeded worker evidence lacks an exact retired provenance marker",
        ));
    };
    Ok(if retired {
        WorkerCreationProvenanceRetirement::Retired(provenance)
    } else {
        WorkerCreationProvenanceRetirement::Active(provenance)
    })
}

fn retire_worker_creation_provenance_state(
    retirement: &WorkerCreationProvenanceRetirement,
) -> io::Result<()> {
    match retirement {
        WorkerCreationProvenanceRetirement::Active(provenance) => {
            retire_worker_creation_provenance(provenance)
        }
        WorkerCreationProvenanceRetirement::Retired(provenance) => {
            verify_retired_worker_creation_provenance(provenance)?;
            sync_worker_creation_provenance_parent(&provenance.parent)?;
            verify_retired_worker_creation_provenance(provenance)
        }
    }
}

fn sync_worker_creation_provenance_parent(parent: &std::fs::File) -> io::Result<()> {
    #[cfg(test)]
    fail_worker_provenance_retirement_at(super::WorkerProvenanceRetirementFault::BeforeParentSync)?;
    parent.sync_all()
}
struct OpenedWorkerDirectory {
    directory: std::fs::File,
    disposition: super::WorkerDirectoryNodeDisposition,
    provenance: Option<WorkerCreationProvenance>,
}

struct WorkerDirectoryOpenError {
    primary: io::Error,
    published: Option<OpenedWorkerDirectory>,
}

impl WorkerDirectoryOpenError {
    fn published(primary: io::Error, published: OpenedWorkerDirectory) -> Self {
        Self {
            primary,
            published: Some(published),
        }
    }

    fn into_parts(self) -> (io::Error, Option<OpenedWorkerDirectory>) {
        (self.primary, self.published)
    }
}

impl std::fmt::Display for WorkerDirectoryOpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.primary.fmt(formatter)
    }
}

impl From<io::Error> for WorkerDirectoryOpenError {
    fn from(primary: io::Error) -> Self {
        Self {
            primary,
            published: None,
        }
    }
}

impl From<WorkerDirectoryOpenError> for io::Error {
    fn from(error: WorkerDirectoryOpenError) -> Self {
        error.primary
    }
}

struct WorkerCreationProvenance {
    parent: std::fs::File,
    name: CString,
    directory: std::fs::File,
    directory_identity: super::WorkerDirectoryIdentity,
    file: std::fs::File,
    file_identity: PrivateFileIdentity,
    expected_record: Vec<u8>,
}

pub(super) struct WorkerDirectoryLease {
    _creation_lock: std::fs::File,
    layout: super::WorkerDirectoryLayout,
    nodes: [std::fs::File; 6],
    creation_provenance: Vec<WorkerCreationProvenance>,
}

pub(super) fn reverify_worker_directory_lease(
    lease: &WorkerDirectoryLease,
    observations: &[super::WorkerDirectoryNodeObservation; 6],
) -> io::Result<()> {
    let expected_uid = revalidate_worker_root_principal(&lease.layout)?.unix_uid()?;
    for provenance in &lease.creation_provenance {
        verify_worker_creation_provenance(provenance)?;
    }
    for (directory, observation) in lease.nodes.iter().zip(observations) {
        verify_worker_directory_security(directory, expected_uid)?;
        if worker_directory_identity(directory)? != observation.identity() {
            return Err(permission_denied(
                "retained worker directory identity changed before release",
            ));
        }
        let reopened = open_existing_worker_path(observation.path())?;
        if worker_directory_identity(&reopened)? != observation.identity() {
            return Err(permission_denied(
                "worker directory path changed before retained evidence release",
            ));
        }
    }
    Ok(())
}

pub(super) fn retire_worker_directory_authority(lease: &WorkerDirectoryLease) -> io::Result<()> {
    // Child evidence is retired before the root record, so a partial cleanup
    // leaves the root transaction visibly incomplete rather than silently
    // converting an unbound creation into an ordinary existing tree.
    for provenance in lease.creation_provenance.iter().rev() {
        retire_worker_creation_provenance(provenance)?;
    }
    Ok(())
}

fn worker_creation_provenance_name(
    destination_parent: &std::fs::File,
    destination_name: &[u8],
) -> io::Result<CString> {
    worker_creation_provenance_name_with_prefix(
        destination_parent,
        destination_name,
        ".styrn-worker-provenance-",
    )
}

fn worker_creation_retired_provenance_name(
    destination_parent: &std::fs::File,
    destination_name: &[u8],
) -> io::Result<CString> {
    worker_creation_provenance_name_with_prefix(
        destination_parent,
        destination_name,
        ".styrn-worker-retired-",
    )
}

fn worker_creation_active_provenance_name_from_retired(
    retired_name: &std::ffi::CStr,
) -> io::Result<CString> {
    const RETIRED_PREFIX: &[u8] = b".styrn-worker-retired-";
    let suffix = retired_name
        .to_bytes()
        .strip_prefix(RETIRED_PREFIX)
        .ok_or_else(|| invalid_data("retired worker provenance name has an invalid prefix"))?;
    let mut name = b".styrn-worker-provenance-".to_vec();
    name.extend_from_slice(suffix);
    CString::new(name).map_err(|_| invalid_data("worker provenance name contains a NUL byte"))
}

fn worker_creation_retired_provenance_name_from_marker(
    marker_name: &std::ffi::CStr,
) -> io::Result<CString> {
    const ACTIVE_PREFIX: &[u8] = b".styrn-worker-provenance-";
    const RETIRED_PREFIX: &[u8] = b".styrn-worker-retired-";
    if marker_name.to_bytes().starts_with(RETIRED_PREFIX) {
        return Ok(marker_name.to_owned());
    }
    let suffix = marker_name
        .to_bytes()
        .strip_prefix(ACTIVE_PREFIX)
        .ok_or_else(|| invalid_data("active worker provenance name has an invalid prefix"))?;
    let mut name = RETIRED_PREFIX.to_vec();
    name.extend_from_slice(suffix);
    CString::new(name).map_err(|_| invalid_data("worker provenance name contains a NUL byte"))
}

fn worker_creation_provenance_name_with_prefix(
    destination_parent: &std::fs::File,
    destination_name: &[u8],
    prefix: &str,
) -> io::Result<CString> {
    use std::fmt::Write;

    let identity = worker_directory_identity(destination_parent)?;
    let mut digest = Sha256::new();
    digest.update(b"styrn-worker-provenance-v1");
    digest.update(identity.volume.to_le_bytes());
    digest.update(identity.file_id);
    digest.update(destination_name);
    let digest = digest.finalize();
    let mut name = String::from(prefix);
    for byte in &digest[..16] {
        write!(&mut name, "{byte:02x}").expect("writing a provenance digest cannot fail");
    }
    CString::new(name).map_err(|_| invalid_data("worker provenance name contains a NUL byte"))
}

fn worker_creation_provenance_record(
    staging_parent: &std::fs::File,
    destination_parent: &std::fs::File,
    destination_name: &[u8],
    created_identity: super::WorkerDirectoryIdentity,
    provenance_directory_identity: super::WorkerDirectoryIdentity,
    provenance_file_identity: PrivateFileIdentity,
    expected_uid: u32,
) -> io::Result<Vec<u8>> {
    let staging_parent = worker_directory_identity(staging_parent)?;
    let destination_parent = worker_directory_identity(destination_parent)?;
    let name_length = u32::try_from(destination_name.len())
        .map_err(|_| invalid_data("worker directory component is too long"))?;
    let mut record = Vec::with_capacity(144 + destination_name.len());
    record.extend_from_slice(b"STYRN-WORKER-PROVENANCE-V2\0");
    for identity in [
        staging_parent,
        destination_parent,
        created_identity,
        provenance_directory_identity,
    ] {
        record.extend_from_slice(&identity.volume.to_le_bytes());
        record.extend_from_slice(&identity.file_id);
    }
    record.extend_from_slice(&provenance_file_identity.first.to_le_bytes());
    record.extend_from_slice(&provenance_file_identity.second.to_le_bytes());
    record.extend_from_slice(&expected_uid.to_le_bytes());
    record.extend_from_slice(&name_length.to_le_bytes());
    record.extend_from_slice(destination_name);
    Ok(record)
}

fn worker_provenance_file_identity(file: &std::fs::File) -> io::Result<PrivateFileIdentity> {
    let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut status) } == -1 {
        return Err(io::Error::last_os_error());
    }
    if status.st_mode & libc::S_IFMT != libc::S_IFREG
        || status.st_mode & 0o777 != 0o600
        || status.st_uid != unsafe { libc::geteuid() }
        || status.st_nlink != 1
    {
        return Err(permission_denied(
            "worker creation provenance is not a private regular file",
        ));
    }
    if posix_acl_present(file, c"system.posix_acl_access")? {
        return Err(permission_denied(
            "worker creation provenance has an access ACL",
        ));
    }
    Ok(PrivateFileIdentity::new(status.st_dev, status.st_ino))
}

fn worker_provenance_identity_at(
    parent: &std::fs::File,
    name: &std::ffi::CStr,
) -> io::Result<PrivateFileIdentity> {
    let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut status,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    if status.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(permission_denied(
            "worker creation provenance path is not a regular file",
        ));
    }
    Ok(PrivateFileIdentity::new(status.st_dev, status.st_ino))
}

fn verify_worker_creation_provenance(provenance: &WorkerCreationProvenance) -> io::Result<()> {
    verify_worker_creation_provenance_at_name(provenance, &provenance.name)
}

fn verify_worker_creation_provenance_at_name(
    provenance: &WorkerCreationProvenance,
    name: &std::ffi::CStr,
) -> io::Result<()> {
    use std::io::{Read, Seek};

    verify_staged_worker_directory_security(
        &provenance.directory,
        unsafe { libc::geteuid() },
        unsafe { libc::geteuid() },
    )?;
    if worker_directory_identity(&provenance.directory)? != provenance.directory_identity
        || worker_directory_identity_at(&provenance.parent, name)? != provenance.directory_identity
        || worker_provenance_file_identity(&provenance.file)? != provenance.file_identity
        || worker_provenance_identity_at(&provenance.directory, c"record")?
            != provenance.file_identity
        || worker_parent_entry_snapshot(&provenance.directory)?
            != vec![(
                b"record".to_vec(),
                super::WorkerDirectoryIdentity::from_unix(
                    provenance.file_identity.first,
                    provenance.file_identity.second,
                ),
            )]
    {
        return Err(permission_denied(
            "worker creation provenance identity changed",
        ));
    }
    let mut reader = provenance.file.try_clone()?;
    reader.rewind()?;
    let mut actual = Vec::new();
    reader.read_to_end(&mut actual)?;
    if actual != provenance.expected_record {
        return Err(permission_denied(
            "worker creation provenance content changed",
        ));
    }
    Ok(())
}

fn verify_retired_worker_creation_provenance(
    provenance: &WorkerCreationProvenance,
) -> io::Result<()> {
    let retired_name = worker_creation_retired_provenance_name_from_marker(&provenance.name)?;
    verify_worker_creation_provenance_at_name(provenance, &retired_name)?;
    let active_name = worker_creation_active_provenance_name_from_retired(&retired_name)?;
    if worker_parent_entry_exists(&provenance.parent, &active_name)? {
        return Err(permission_denied(
            "active and retired worker provenance markers both exist",
        ));
    }
    Ok(())
}

fn create_worker_creation_provenance(
    staging_parent: &std::fs::File,
    destination_parent: &std::fs::File,
    destination_name: &[u8],
    created_identity: super::WorkerDirectoryIdentity,
    expected_uid: u32,
) -> io::Result<WorkerCreationProvenance> {
    use std::io::Write;

    let name = worker_creation_provenance_name(destination_parent, destination_name)?;
    let retired_name =
        worker_creation_retired_provenance_name(destination_parent, destination_name)?;
    let entries_before = worker_parent_entry_snapshot(staging_parent)?;
    if entries_before
        .iter()
        .any(|(entry, _)| entry == retired_name.to_bytes())
    {
        return Err(permission_denied(
            "retired worker provenance conflicts with a new creation",
        ));
    }
    if unsafe { libc::mkdirat(staging_parent.as_raw_fd(), name.as_ptr(), 0o700) } == -1 {
        let error = io::Error::last_os_error();
        return Err(if error.kind() == io::ErrorKind::AlreadyExists {
            permission_denied("worker creation provenance already exists ambiguously")
        } else {
            error
        });
    }
    let directory = open_worker_directory_at(staging_parent, name.to_bytes())?;
    let directory_identity = worker_directory_identity(&directory)?;
    let mut expected_entries = entries_before;
    expected_entries.push((name.to_bytes().to_vec(), directory_identity));
    expected_entries.sort_by(|left, right| left.0.cmp(&right.0));
    if worker_parent_entry_snapshot(staging_parent)? != expected_entries {
        return Err(permission_denied(
            "worker creation provenance directory changed before its first retained handle",
        ));
    }
    harden_new_worker_directory(&directory, unsafe { libc::geteuid() })?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c"record".as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(descriptor) };
    clear_posix_acl(&file, c"system.posix_acl_access")?;
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let file_identity = worker_provenance_file_identity(&file)?;
    let expected_record = worker_creation_provenance_record(
        staging_parent,
        destination_parent,
        destination_name,
        created_identity,
        directory_identity,
        file_identity,
        expected_uid,
    )?;
    file.write_all(&expected_record)?;
    file.sync_all()?;
    directory.sync_all()?;
    staging_parent.sync_all()?;
    let provenance = WorkerCreationProvenance {
        parent: staging_parent.try_clone()?,
        name,
        directory,
        directory_identity,
        file,
        file_identity,
        expected_record,
    };
    verify_worker_creation_provenance(&provenance)?;
    Ok(provenance)
}

fn open_worker_creation_provenance(
    staging_parent: &std::fs::File,
    destination_parent: &std::fs::File,
    destination_name: &[u8],
    created_identity: super::WorkerDirectoryIdentity,
    expected_uid: u32,
) -> io::Result<Option<WorkerCreationProvenance>> {
    let name = worker_creation_provenance_name(destination_parent, destination_name)?;
    open_worker_creation_provenance_at_name(
        staging_parent,
        destination_parent,
        destination_name,
        created_identity,
        expected_uid,
        name,
    )
}

fn open_retired_worker_creation_provenance(
    staging_parent: &std::fs::File,
    destination_parent: &std::fs::File,
    destination_name: &[u8],
    created_identity: super::WorkerDirectoryIdentity,
    expected_uid: u32,
) -> io::Result<Option<WorkerCreationProvenance>> {
    let name = worker_creation_retired_provenance_name(destination_parent, destination_name)?;
    let provenance = open_worker_creation_provenance_at_name(
        staging_parent,
        destination_parent,
        destination_name,
        created_identity,
        expected_uid,
        name,
    )?;
    if let Some(provenance) = &provenance {
        verify_retired_worker_creation_provenance(provenance)?;
    }
    Ok(provenance)
}

fn open_worker_creation_provenance_at_name(
    staging_parent: &std::fs::File,
    destination_parent: &std::fs::File,
    destination_name: &[u8],
    created_identity: super::WorkerDirectoryIdentity,
    expected_uid: u32,
    name: CString,
) -> io::Result<Option<WorkerCreationProvenance>> {
    let directory = match open_worker_directory_at(staging_parent, name.to_bytes()) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    verify_staged_worker_directory_security(&directory, unsafe { libc::geteuid() }, unsafe {
        libc::geteuid()
    })?;
    let directory_identity = worker_directory_identity(&directory)?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c"record".as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor == -1 {
        let error = worker_directory_open_error(io::Error::last_os_error());
        return Err(if error.kind() == io::ErrorKind::NotFound {
            permission_denied("worker creation provenance record is missing")
        } else {
            error
        });
    }
    let file = unsafe { std::fs::File::from_raw_fd(descriptor) };
    let file_identity = worker_provenance_file_identity(&file)?;
    let expected_record = worker_creation_provenance_record(
        staging_parent,
        destination_parent,
        destination_name,
        created_identity,
        directory_identity,
        file_identity,
        expected_uid,
    )?;
    let provenance = WorkerCreationProvenance {
        parent: staging_parent.try_clone()?,
        name,
        directory,
        directory_identity,
        file,
        file_identity,
        expected_record,
    };
    verify_worker_creation_provenance(&provenance)?;
    Ok(Some(provenance))
}

fn absolute_worker_components(path: &Path) -> io::Result<Vec<&[u8]>> {
    let mut components = path.components();
    if !matches!(components.next(), Some(std::path::Component::RootDir)) {
        return Err(invalid_data("worker directory path is not absolute"));
    }
    components
        .map(|component| match component {
            std::path::Component::Normal(name) => Ok(name.as_bytes()),
            _ => Err(invalid_data("worker directory path is not normalized")),
        })
        .collect()
}

fn worker_first_creatable_component(
    layout: &super::WorkerDirectoryLayout,
    root_components: &[&[u8]],
) -> io::Result<usize> {
    match &layout.creation_policy {
        super::WorkerRootCreationPolicy::ExistingParent { .. } => root_components
            .len()
            .checked_sub(1)
            .ok_or_else(|| invalid_data("worker root has no leaf component")),
        super::WorkerRootCreationPolicy::CreateMissingFrom(anchor) => {
            let anchor_components = absolute_worker_components(anchor)?;
            if !root_components.starts_with(&anchor_components)
                || root_components.len() == anchor_components.len()
            {
                return Err(permission_denied(
                    "worker standard root escapes its native profile anchor",
                ));
            }
            Ok(anchor_components.len())
        }
    }
}

fn worker_creation_anchor_path(layout: &super::WorkerDirectoryLayout) -> io::Result<PathBuf> {
    match &layout.creation_policy {
        super::WorkerRootCreationPolicy::ExistingParent { .. } => layout
            .root()
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| invalid_data("worker root has no fixed parent anchor")),
        super::WorkerRootCreationPolicy::CreateMissingFrom(anchor) => Ok(anchor.clone()),
    }
}

fn open_worker_creation_anchor(
    root_components: &[&[u8]],
    first_creatable: usize,
    expected_uid: u32,
) -> io::Result<std::fs::File> {
    let mut anchor = open_worker_filesystem_root()?;
    verify_worker_creation_ancestor(&anchor, expected_uid)?;
    for component in &root_components[..first_creatable] {
        anchor = open_worker_directory_at(&anchor, component)?;
        verify_worker_creation_ancestor(&anchor, expected_uid)?;
    }
    Ok(anchor)
}

fn open_worker_filesystem_root() -> io::Result<std::fs::File> {
    let descriptor = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
}

fn open_existing_worker_path(path: &Path) -> io::Result<std::fs::File> {
    let mut directory = open_worker_filesystem_root()?;
    for component in absolute_worker_components(path)? {
        directory = open_worker_directory_at(&directory, component)?;
    }
    Ok(directory)
}

fn verify_worker_path_identity(
    path: &Path,
    expected: super::WorkerDirectoryIdentity,
) -> io::Result<()> {
    let reopened = open_existing_worker_path(path)?;
    if worker_directory_identity(&reopened)? != expected {
        return Err(permission_denied(
            "worker root pathname changed during layout creation",
        ));
    }
    Ok(())
}

fn open_or_create_worker_directory_at(
    staging_parent: &std::fs::File,
    parent: &std::fs::File,
    name: &[u8],
    may_create: bool,
    expected_uid: u32,
    existing_must_be_canonical: bool,
    unpublished_parent: Option<&CreatorOnlyUnpublishedParent<'_>>,
) -> Result<OpenedWorkerDirectory, WorkerDirectoryOpenError> {
    match open_worker_directory_at(parent, name) {
        Ok(directory) => {
            let created_identity = worker_recovery_candidate_identity(name, &directory)?;
            let active = open_worker_creation_provenance(
                staging_parent,
                parent,
                name,
                created_identity,
                expected_uid,
            )?;
            let retired = open_retired_worker_creation_provenance(
                staging_parent,
                parent,
                name,
                created_identity,
                expected_uid,
            )?;
            if active.is_some() && retired.is_some() {
                return Err(permission_denied(
                    "active and retired worker provenance markers both exist",
                )
                .into());
            }
            if let Some(provenance) = active {
                if let Some(authority) = unpublished_parent {
                    authority.reverify_parent(parent)?;
                    if authority.worker_uid != expected_uid || !existing_must_be_canonical {
                        return Err(permission_denied(
                            "unpublished parent authority does not match the canonical worker child",
                        ).into());
                    }
                    verify_existing_worker_directory(
                        &directory,
                        expected_uid,
                        existing_must_be_canonical,
                    )?;
                    return Ok(OpenedWorkerDirectory {
                        directory,
                        disposition: super::WorkerDirectoryNodeDisposition::Created,
                        provenance: Some(provenance),
                    });
                }
                return Err(permission_denied(
                    "published worker creation provenance is replayable conflict evidence, not receipt ownership",
                ).into());
            }
            drop(retired);
            verify_existing_worker_directory(&directory, expected_uid, existing_must_be_canonical)?;
            return Ok(OpenedWorkerDirectory {
                directory,
                disposition: super::WorkerDirectoryNodeDisposition::Existing,
                provenance: None,
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && may_create => {
            let active_name = worker_creation_provenance_name(parent, name)?;
            let retired_name = worker_creation_retired_provenance_name(parent, name)?;
            if worker_parent_entry_exists(staging_parent, &active_name)?
                || worker_parent_entry_exists(staging_parent, &retired_name)?
            {
                return Err(permission_denied(
                    "worker creation evidence exists without its exact destination directory",
                )
                .into());
            }
        }
        Err(error) => return Err(error.into()),
    }
    let staged =
        create_unpublished_worker_directory(staging_parent, parent, name, expected_uid, false)?;
    publish_staged_worker_directory(
        staging_parent,
        staged,
        parent,
        name,
        expected_uid,
        expected_uid,
        existing_must_be_canonical,
    )
}

fn create_or_open_complete_worker_root(
    root_parent: &std::fs::File,
    root_name: &[u8],
    expected_uid: u32,
) -> io::Result<(
    OpenedWorkerDirectory,
    Option<Vec<Option<OpenedWorkerDirectory>>>,
)> {
    match open_worker_directory_at(root_parent, root_name) {
        Ok(directory) => {
            let created_identity = worker_recovery_candidate_identity(root_name, &directory)?;
            let active = open_worker_creation_provenance(
                root_parent,
                root_parent,
                root_name,
                created_identity,
                expected_uid,
            )?;
            let retired = open_retired_worker_creation_provenance(
                root_parent,
                root_parent,
                root_name,
                created_identity,
                expected_uid,
            )?;
            if active.is_some() && retired.is_some() {
                return Err(permission_denied(
                    "active and retired worker provenance markers both exist",
                ));
            }
            if let Some(provenance) = active {
                drop(provenance);
                return Err(permission_denied(
                    "published worker creation provenance is replayable conflict evidence, not receipt ownership",
                ));
            }
            drop(retired);
            verify_worker_directory_security(&directory, expected_uid)?;
            return Ok((
                OpenedWorkerDirectory {
                    directory,
                    disposition: super::WorkerDirectoryNodeDisposition::Existing,
                    provenance: None,
                },
                None,
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let active_name = worker_creation_provenance_name(root_parent, root_name)?;
            let retired_name = worker_creation_retired_provenance_name(root_parent, root_name)?;
            if worker_parent_entry_exists(root_parent, &active_name)?
                || worker_parent_entry_exists(root_parent, &retired_name)?
            {
                return Err(permission_denied(
                    "worker creation evidence exists without its exact destination directory",
                ));
            }
        }
        Err(error) => return Err(error),
    }

    let staged = create_unpublished_worker_directory(
        root_parent,
        root_parent,
        root_name,
        expected_uid,
        true,
    )?;
    maybe_interrupt_worker_mkdir();
    let children_result = {
        let recovery_authority = verify_unpublished_worker_recovery_authority(
            &staged,
            root_parent,
            root_parent,
            root_name,
            expected_uid,
        )?;
        open_or_create_worker_children(
            root_parent,
            &staged.directory,
            expected_uid,
            !staged.created,
            recovery_authority.as_ref(),
        )
    };
    let children = match children_result {
        Ok(children) => children,
        Err(error) => return fail_after_staged_tree_cleanup(error, root_parent, &staged),
    };
    let root = publish_staged_worker_directory(
        root_parent,
        staged,
        root_parent,
        root_name,
        expected_uid,
        expected_uid,
        true,
    )?;
    Ok((root, Some(children)))
}

fn fail_after_staged_tree_cleanup<T>(
    original: io::Error,
    parent: &std::fs::File,
    staged: &StagedWorkerDirectory,
) -> io::Result<T> {
    if !staged.created
        || worker_parent_entry_snapshot(parent)?
            .iter()
            .any(|(name, _)| {
                name.starts_with(b".styrn-worker-provenance-")
                    || name.starts_with(b".styrn-worker-retired-")
            })
    {
        return Err(original);
    }
    match remove_known_staged_worker_tree(parent, staged) {
        Ok(()) => Err(original),
        Err(cleanup) => Err(cleanup),
    }
}

fn open_or_create_worker_children(
    staging_parent: &std::fs::File,
    root: &std::fs::File,
    expected_uid: u32,
    require_provenance_for_existing: bool,
    unpublished_parent: Option<&CreatorOnlyUnpublishedParent<'_>>,
) -> io::Result<Vec<Option<OpenedWorkerDirectory>>> {
    let mut children = Vec::with_capacity(super::WorkerDirectoryLayout::child_names().len());
    for name in super::WorkerDirectoryLayout::child_names() {
        let child = open_or_create_worker_directory_at(
            staging_parent,
            root,
            name.as_bytes(),
            true,
            expected_uid,
            true,
            unpublished_parent,
        )?;
        if require_provenance_for_existing
            && child.disposition == super::WorkerDirectoryNodeDisposition::Existing
        {
            return Err(permission_denied(
                "interrupted worker staging child lacks exact creation provenance",
            ));
        }
        children.push(Some(child));
    }
    Ok(children)
}

fn remove_known_staged_worker_tree(
    parent: &std::fs::File,
    staged: &StagedWorkerDirectory,
) -> io::Result<()> {
    for name in super::WorkerDirectoryLayout::child_names() {
        let canonical =
            CString::new(name).expect("canonical worker child names contain no NUL bytes");
        remove_known_empty_staging_child(&staged.directory, &canonical)?;
        let internal = worker_staging_name(&staged.directory, name.as_bytes())?;
        remove_known_empty_staging_child(&staged.directory, &internal)?;
    }
    remove_exact_empty_staged_worker_directory(parent, staged)
}

fn remove_known_empty_staging_child(parent: &std::fs::File, name: &CString) -> io::Result<()> {
    match open_worker_directory_at(parent, name.to_bytes()) {
        Ok(child) => {
            let expected = worker_directory_identity(&child)?;
            if worker_directory_identity_at(parent, name)? != expected {
                return Err(permission_denied(
                    "worker staging child changed before private cleanup",
                ));
            }
            if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
                == -1
            {
                return Err(io::Error::last_os_error());
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

struct StagedWorkerDirectory {
    name: CString,
    directory: std::fs::File,
    identity: super::WorkerDirectoryIdentity,
    created: bool,
}

fn create_unpublished_worker_directory(
    staging_parent: &std::fs::File,
    destination_parent: &std::fs::File,
    destination_name: &[u8],
    expected_uid: u32,
    allow_canonical_children: bool,
) -> io::Result<StagedWorkerDirectory> {
    let name = worker_staging_name(destination_parent, destination_name)?;
    let entries_before = worker_parent_entry_snapshot(staging_parent)?;
    let created =
        if unsafe { libc::mkdirat(staging_parent.as_raw_fd(), name.as_ptr(), 0o700) } == -1 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(worker_directory_open_error(error));
            }
            false
        } else {
            true
        };
    if created {
        #[cfg(test)]
        POST_WORKER_MKDIR_HOOK.with(|slot| {
            if let Some(hook) = slot.take() {
                hook(staging_parent.as_raw_fd(), &name);
            }
        });
    }
    let directory = open_worker_directory_at(staging_parent, name.to_bytes())?;
    let identity = worker_directory_identity(&directory)?;
    if created {
        let mut expected_entries = entries_before;
        expected_entries.push((name.to_bytes().to_vec(), identity));
        expected_entries.sort_by(|left, right| left.0.cmp(&right.0));
        if worker_parent_entry_snapshot(staging_parent)? != expected_entries {
            return Err(permission_denied(
                "new worker staging directory ancestry changed before its first retained handle",
            ));
        }
    }
    let creator_uid = unsafe { libc::geteuid() };
    if created {
        harden_new_worker_directory(&directory, creator_uid)?;
    } else {
        // User scope deliberately does not claim containment against hostile same-UID code.
        // The fixed name still lets an interrupted run retain and validate exact inode state.
        verify_staged_worker_directory_security(&directory, creator_uid, expected_uid)?;
        verify_staged_worker_directory_entries(&directory, allow_canonical_children)?;
    }
    Ok(StagedWorkerDirectory {
        name,
        directory,
        identity,
        created,
    })
}

fn worker_parent_entry_snapshot(
    parent: &std::fs::File,
) -> io::Result<Vec<(Vec<u8>, super::WorkerDirectoryIdentity)>> {
    let duplicate = unsafe { libc::fcntl(parent.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate == -1 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(io::Error::last_os_error());
    }
    let stream = OwnedDirectoryStream(stream);
    unsafe { libc::rewinddir(stream.0) };
    let mut entries = Vec::new();
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = unsafe { *libc::__errno_location() };
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                &mut status,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
        entries.push((
            name.to_bytes().to_vec(),
            super::WorkerDirectoryIdentity::from_unix(status.st_dev, status.st_ino),
        ));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

fn maybe_interrupt_worker_mkdir() {
    #[cfg(test)]
    WORKER_MKDIR_INTERRUPT_AFTER.with(|slot| {
        if let Some(remaining) = slot.get() {
            if remaining == 0 {
                slot.set(None);
                panic!("injected worker staging interruption");
            }
            slot.set(Some(remaining - 1));
        }
    });
}

fn maybe_interrupt_worker_publication(complete_root: bool, phase: WorkerPublicationInterruption) {
    #[cfg(test)]
    if complete_root {
        WORKER_PUBLICATION_INTERRUPT.with(|slot| {
            if slot.get() == Some(phase) {
                slot.set(None);
                panic!("injected worker publication interruption");
            }
        });
    }
    #[cfg(not(test))]
    let _ = (complete_root, phase);
}

fn worker_staging_name(
    destination_parent: &std::fs::File,
    destination_name: &[u8],
) -> io::Result<CString> {
    use std::fmt::Write;

    let identity = worker_directory_identity(destination_parent)?;
    let mut digest = Sha256::new();
    digest.update(identity.volume.to_le_bytes());
    digest.update(identity.file_id);
    digest.update(destination_name);
    let digest = digest.finalize();
    let mut name = String::from(".styrn-worker-stage-");
    for byte in &digest[..16] {
        write!(&mut name, "{byte:02x}").expect("writing a staging digest cannot fail");
    }
    CString::new(name).map_err(|_| invalid_data("worker staging name contains a NUL byte"))
}

fn verify_staged_worker_directory_security(
    directory: &std::fs::File,
    creator_uid: u32,
    expected_uid: u32,
) -> io::Result<()> {
    let status = worker_directory_status(directory)?;
    if !matches!(status.st_uid, uid if uid == creator_uid || uid == expected_uid)
        || status.st_mode & 0o777 != 0o700
    {
        return Err(permission_denied(
            "reserved worker staging directory has ambiguous ownership or mode",
        ));
    }
    validate_worker_acl_presence(
        posix_acl_present(directory, c"system.posix_acl_access")?,
        posix_acl_present(directory, c"system.posix_acl_default")?,
    )
}

fn verify_staged_or_published_worker_directory(
    directory: &std::fs::File,
    expected_uid: u32,
) -> io::Result<()> {
    verify_staged_worker_directory_security(directory, unsafe { libc::geteuid() }, expected_uid)
}

struct CreatorOnlyUnpublishedParent<'authority> {
    parent: &'authority std::fs::File,
    identity: super::WorkerDirectoryIdentity,
    staging_parent: &'authority std::fs::File,
    staging_parent_identity: super::WorkerDirectoryIdentity,
    staging_name: CString,
    canonical_parent: &'authority std::fs::File,
    canonical_parent_identity: super::WorkerDirectoryIdentity,
    canonical_name: CString,
    creator_uid: u32,
    worker_uid: u32,
}

impl CreatorOnlyUnpublishedParent<'_> {
    fn reverify_parent(&self, destination_parent: &std::fs::File) -> io::Result<()> {
        if self.creator_uid == self.worker_uid
            || unsafe { libc::geteuid() } != self.creator_uid
            || worker_directory_identity(self.parent)? != self.identity
            || worker_directory_identity(destination_parent)? != self.identity
        {
            return Err(permission_denied(
                "unpublished worker parent authority no longer names the retained directory",
            ));
        }
        if worker_directory_identity(self.staging_parent)? != self.staging_parent_identity
            || worker_directory_identity(self.canonical_parent)? != self.canonical_parent_identity
            || worker_directory_identity_at(self.staging_parent, &self.staging_name).map_err(
                |_| {
                    permission_denied(
                        "unpublished worker parent no longer occupies its retained staging name",
                    )
                },
            )? != self.identity
        {
            return Err(permission_denied(
                "unpublished worker parent no longer occupies its retained staging name",
            ));
        }
        match worker_directory_identity_at(self.canonical_parent, &self.canonical_name) {
            Ok(identity) if identity == self.identity => {
                return Err(permission_denied(
                    "unpublished worker parent was published at its canonical destination",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(permission_denied(
                    "canonical worker destination cannot be reverified as absent or different",
                ));
            }
        }
        let status = worker_directory_status(self.parent)?;
        if status.st_uid != self.creator_uid || status.st_mode & 0o777 != 0o700 {
            return Err(permission_denied(
                "unpublished worker parent is no longer creator-only",
            ));
        }
        validate_worker_acl_presence(
            posix_acl_present(self.parent, c"system.posix_acl_access")?,
            posix_acl_present(self.parent, c"system.posix_acl_default")?,
        )
    }
}

fn verify_unpublished_worker_recovery_authority<'authority>(
    staged: &'authority StagedWorkerDirectory,
    staging_parent: &'authority std::fs::File,
    canonical_parent: &'authority std::fs::File,
    canonical_name: &[u8],
    expected_uid: u32,
) -> io::Result<Option<CreatorOnlyUnpublishedParent<'authority>>> {
    if staged.created {
        return Ok(None);
    }
    // A reopened inode number is replayable. Recovery is automatic only while
    // this complete candidate is still inaccessible to a distinct worker.
    let creator_uid = unsafe { libc::geteuid() };
    let status = worker_directory_status(&staged.directory)?;
    if creator_uid == expected_uid
        || status.st_uid != creator_uid
        || status.st_mode & 0o777 != 0o700
    {
        return Err(permission_denied(
            "interrupted worker staging recovery lacks distinct creator-only authority",
        ));
    }
    validate_worker_acl_presence(
        posix_acl_present(&staged.directory, c"system.posix_acl_access")?,
        posix_acl_present(&staged.directory, c"system.posix_acl_default")?,
    )?;
    if worker_directory_identity(&staged.directory)? != staged.identity {
        return Err(permission_denied(
            "interrupted worker staging parent identity changed",
        ));
    }
    let authority = CreatorOnlyUnpublishedParent {
        parent: &staged.directory,
        identity: staged.identity,
        staging_parent,
        staging_parent_identity: worker_directory_identity(staging_parent)?,
        staging_name: staged.name.clone(),
        canonical_parent,
        canonical_parent_identity: worker_directory_identity(canonical_parent)?,
        canonical_name: CString::new(canonical_name)
            .map_err(|_| invalid_data("worker directory component contains a NUL byte"))?,
        creator_uid,
        worker_uid: expected_uid,
    };
    authority.reverify_parent(&staged.directory)?;
    Ok(Some(authority))
}

fn verify_staged_worker_directory_entries(
    directory: &std::fs::File,
    allow_canonical_children: bool,
) -> io::Result<()> {
    let canonical_names = super::WorkerDirectoryLayout::child_names();
    let internal_names = canonical_names
        .iter()
        .map(|child| worker_staging_name(directory, child.as_bytes()))
        .collect::<io::Result<Vec<_>>>()?;
    let mut canonical_seen = [false; 5];
    let mut internal_seen = [false; 5];
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate == -1 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(io::Error::last_os_error());
    }
    let stream = OwnedDirectoryStream(stream);
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = unsafe { *libc::__errno_location() };
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        let canonical = canonical_names
            .iter()
            .position(|allowed| allowed.as_bytes() == name);
        let internal = internal_names
            .iter()
            .position(|allowed| allowed.as_bytes() == name);
        let Some((index, staged)) = canonical
            .map(|index| (index, false))
            .or_else(|| internal.map(|index| (index, true)))
        else {
            return Err(permission_denied(
                "reserved worker staging directory contains an unrelated entry",
            ));
        };
        if !allow_canonical_children || canonical_seen[index] || internal_seen[index] {
            return Err(permission_denied(
                "reserved worker staging directory has an ambiguous child state",
            ));
        }
        if staged {
            internal_seen[index] = true;
        } else {
            canonical_seen[index] = true;
        }
    }
    Ok(())
}

struct OwnedDirectoryStream(*mut libc::DIR);

impl Drop for OwnedDirectoryStream {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}

fn publish_staged_worker_directory(
    staging_parent: &std::fs::File,
    staged: StagedWorkerDirectory,
    destination_parent: &std::fs::File,
    destination_name: &[u8],
    created_expected_uid: u32,
    existing_expected_uid: u32,
    existing_must_be_canonical: bool,
) -> Result<OpenedWorkerDirectory, WorkerDirectoryOpenError> {
    let complete_root = existing_must_be_canonical
        && worker_directory_identity(staging_parent)?
            == worker_directory_identity(destination_parent)?;
    let destination_name = CString::new(destination_name)
        .map_err(|_| invalid_data("worker directory component contains a NUL byte"))?;
    verify_staged_worker_directory_security(
        &staged.directory,
        unsafe { libc::geteuid() },
        created_expected_uid,
    )?;
    drop(verify_unpublished_worker_recovery_authority(
        &staged,
        staging_parent,
        destination_parent,
        destination_name.to_bytes(),
        created_expected_uid,
    )?);
    let active_provenance = open_worker_creation_provenance(
        staging_parent,
        destination_parent,
        destination_name.to_bytes(),
        staged.identity,
        created_expected_uid,
    )?;
    if open_retired_worker_creation_provenance(
        staging_parent,
        destination_parent,
        destination_name.to_bytes(),
        staged.identity,
        created_expected_uid,
    )?
    .is_some()
    {
        return Err(permission_denied(
            "retired worker provenance conflicts with an unpublished candidate",
        )
        .into());
    }
    let provenance = match active_provenance {
        Some(provenance) => provenance,
        None if staged.created => create_worker_creation_provenance(
            staging_parent,
            destination_parent,
            destination_name.to_bytes(),
            staged.identity,
            created_expected_uid,
        )?,
        None => {
            return Err(permission_denied(
                "interrupted worker staging directory lacks exact creation provenance",
            )
            .into());
        }
    };
    maybe_interrupt_worker_publication(
        complete_root,
        WorkerPublicationInterruption::AfterProvenance,
    );
    if complete_root {
        maybe_interrupt_worker_mkdir();
    }
    if unsafe {
        libc::renameat2(
            staging_parent.as_raw_fd(),
            staged.name.as_ptr(),
            destination_parent.as_raw_fd(),
            destination_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } == 0
    {
        let opened = OpenedWorkerDirectory {
            directory: staged.directory,
            disposition: super::WorkerDirectoryNodeDisposition::Created,
            provenance: Some(provenance),
        };
        let finish = (|| -> io::Result<()> {
            #[cfg(test)]
            fail_worker_node_post_publish_at(super::WorkerNodePostPublishFault::AfterRename)?;
            #[cfg(test)]
            fail_worker_node_post_publish_at(
                super::WorkerNodePostPublishFault::BeforeDestinationReopen,
            )?;
            let reopened =
                open_worker_directory_at(destination_parent, destination_name.to_bytes())?;
            #[cfg(test)]
            fail_worker_node_post_publish_at(
                super::WorkerNodePostPublishFault::BeforeIdentityCheck,
            )?;
            if worker_directory_identity(&reopened)? != staged.identity {
                return Err(permission_denied(
                    "published worker directory identity changed before verification",
                ));
            }
            #[cfg(test)]
            fail_worker_node_post_publish_at(
                super::WorkerNodePostPublishFault::BeforeFirstParentSync,
            )?;
            destination_parent.sync_all()?;
            if existing_must_be_canonical && !complete_root {
                #[cfg(test)]
                fail_worker_node_post_publish_at(
                    super::WorkerNodePostPublishFault::BeforeHardening,
                )?;
                harden_new_worker_directory(&opened.directory, created_expected_uid)?;
                #[cfg(test)]
                fail_worker_node_post_publish_at(
                    super::WorkerNodePostPublishFault::BeforeNodeSync,
                )?;
                opened.directory.sync_all()?;
                #[cfg(test)]
                fail_worker_node_post_publish_at(
                    super::WorkerNodePostPublishFault::BeforeSecondParentSync,
                )?;
                destination_parent.sync_all()?;
                #[cfg(test)]
                fail_worker_node_post_publish_at(
                    super::WorkerNodePostPublishFault::BeforeSecurityCheck,
                )?;
                verify_worker_directory_security(&opened.directory, created_expected_uid)?;
            } else {
                verify_staged_or_published_worker_directory(
                    &opened.directory,
                    created_expected_uid,
                )?;
            }
            Ok(())
        })();
        return match finish {
            Ok(()) => Ok(opened),
            Err(error) => Err(WorkerDirectoryOpenError::published(error, opened)),
        };
    }
    let error = io::Error::last_os_error();
    if error.kind() != io::ErrorKind::AlreadyExists {
        return Err(error.into());
    }
    let directory = open_worker_directory_at(destination_parent, destination_name.to_bytes())?;
    if worker_directory_identity(&directory)? != staged.identity {
        return Err(permission_denied(
            "worker publication conflict retains exact creation evidence",
        )
        .into());
    }
    verify_staged_or_published_worker_directory(&directory, existing_expected_uid)?;
    if existing_must_be_canonical && !complete_root {
        harden_new_worker_directory(&directory, existing_expected_uid)?;
        verify_existing_worker_directory(
            &directory,
            existing_expected_uid,
            existing_must_be_canonical,
        )?;
    }
    Ok(OpenedWorkerDirectory {
        directory,
        disposition: super::WorkerDirectoryNodeDisposition::Created,
        provenance: Some(provenance),
    })
}

fn worker_directory_identity_at(
    parent: &std::fs::File,
    name: &std::ffi::CStr,
) -> io::Result<super::WorkerDirectoryIdentity> {
    let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut status,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    if status.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(permission_denied(
            "worker staging path is not a real directory",
        ));
    }
    Ok(super::WorkerDirectoryIdentity::from_unix(
        status.st_dev,
        status.st_ino,
    ))
}

fn remove_exact_empty_staged_worker_directory(
    parent: &std::fs::File,
    staged: &StagedWorkerDirectory,
) -> io::Result<()> {
    if worker_directory_identity_at(parent, &staged.name)? != staged.identity {
        return Err(permission_denied(
            "worker staging directory changed before private cleanup",
        ));
    }
    if unsafe { libc::unlinkat(parent.as_raw_fd(), staged.name.as_ptr(), libc::AT_REMOVEDIR) } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn verify_existing_worker_directory(
    directory: &std::fs::File,
    expected_uid: u32,
    must_be_canonical: bool,
) -> io::Result<()> {
    if must_be_canonical {
        verify_worker_directory_security(directory, expected_uid)
    } else {
        verify_worker_creation_ancestor(directory, expected_uid)
    }
}

fn harden_new_worker_directory(directory: &std::fs::File, expected_uid: u32) -> io::Result<()> {
    clear_posix_acl(directory, c"system.posix_acl_access")?;
    clear_posix_acl(directory, c"system.posix_acl_default")?;
    if unsafe { libc::fchown(directory.as_raw_fd(), expected_uid, !0 as libc::gid_t) } == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } == -1 {
        return Err(io::Error::last_os_error());
    }
    verify_worker_directory_security(directory, expected_uid)
}

fn verify_worker_directory_security(
    directory: &std::fs::File,
    expected_uid: u32,
) -> io::Result<()> {
    let status = worker_directory_status(directory)?;
    if status.st_uid != expected_uid || status.st_mode & 0o777 != 0o700 {
        return Err(permission_denied(
            "worker directory owner or mode does not match the exact policy",
        ));
    }
    let access = posix_acl_present(directory, c"system.posix_acl_access")?;
    let default = posix_acl_present(directory, c"system.posix_acl_default")?;
    validate_worker_acl_presence(access, default)
}

fn open_worker_directory_at(parent: &std::fs::File, name: &[u8]) -> io::Result<std::fs::File> {
    let name = CString::new(name)
        .map_err(|_| invalid_data("worker directory component contains a NUL byte"))?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor == -1 {
        return Err(worker_directory_open_error(io::Error::last_os_error()));
    }
    let directory = unsafe { std::fs::File::from_raw_fd(descriptor) };
    worker_directory_identity(&directory)?;
    Ok(directory)
}

fn worker_directory_identity(
    directory: &std::fs::File,
) -> io::Result<super::WorkerDirectoryIdentity> {
    let status = worker_directory_status(directory)?;
    Ok(super::WorkerDirectoryIdentity::from_unix(
        status.st_dev,
        status.st_ino,
    ))
}

fn worker_directory_status(directory: &std::fs::File) -> io::Result<libc::stat> {
    let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(directory.as_raw_fd(), &mut status) } == -1 {
        return Err(io::Error::last_os_error());
    }
    if status.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(permission_denied(
            "worker layout path is not a real directory",
        ));
    }
    Ok(status)
}

fn verify_worker_creation_ancestor(directory: &std::fs::File, expected_uid: u32) -> io::Result<()> {
    let status = worker_directory_status(directory)?;
    let creator_uid = unsafe { libc::geteuid() };
    if (expected_uid != creator_uid && status.st_uid == expected_uid)
        || (status.st_uid != 0 && status.st_uid != expected_uid)
        || (status.st_mode & 0o022 != 0
            && !(status.st_uid == 0 && status.st_mode & libc::S_ISVTX != 0))
    {
        return Err(permission_denied(
            "worker root ancestor does not preserve creator authority over unpublished staging",
        ));
    }
    if posix_acl_present(directory, c"system.posix_acl_access")? {
        return Err(permission_denied(
            "worker root ancestor has an untrusted access ACL",
        ));
    }
    Ok(())
}

fn posix_acl_present(directory: &std::fs::File, name: &std::ffi::CStr) -> io::Result<bool> {
    let acl_size = unsafe {
        libc::fgetxattr(
            directory.as_raw_fd(),
            name.as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if acl_size >= 0 {
        return Ok(acl_size > 0);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENODATA | libc::ENOTSUP) => Ok(false),
        _ => Err(error),
    }
}

#[cfg(test)]
pub(super) fn seed_incompatible_worker_directory_acl_for_action_test(
    path: &Path,
    _principal: &WorkerPrincipal,
) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let mut value = 2_u32.to_le_bytes().to_vec();
    for (tag, permissions, id) in [
        (0x01_u16, 0x07_u16, u32::MAX),
        (
            0x02_u16,
            0x07_u16,
            unsafe { libc::geteuid() }.wrapping_add(1),
        ),
        (0x04_u16, 0x00_u16, u32::MAX),
        (0x10_u16, 0x07_u16, u32::MAX),
        (0x20_u16, 0x00_u16, u32::MAX),
    ] {
        value.extend_from_slice(&tag.to_le_bytes());
        value.extend_from_slice(&permissions.to_le_bytes());
        value.extend_from_slice(&id.to_le_bytes());
    }
    if unsafe {
        libc::setxattr(
            path.as_ptr(),
            c"system.posix_acl_access".as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn worker_directory_acl_is_incompatible_for_action_test(
    path: &Path,
    _principal: &WorkerPrincipal,
) -> io::Result<bool> {
    let directory = std::fs::File::open(path)?;
    posix_acl_present(&directory, c"system.posix_acl_access")
}

fn clear_posix_acl(directory: &std::fs::File, name: &std::ffi::CStr) -> io::Result<()> {
    if unsafe { libc::fremovexattr(directory.as_raw_fd(), name.as_ptr()) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENODATA | libc::ENOTSUP) => Ok(()),
        _ => Err(error),
    }
}

fn validate_worker_acl_presence(access: bool, default: bool) -> io::Result<()> {
    if access || default {
        return Err(permission_denied(
            "worker directory has an access or default ACL",
        ));
    }
    Ok(())
}

fn worker_directory_open_error(error: io::Error) -> io::Error {
    match error.raw_os_error() {
        Some(libc::ELOOP | libc::ENOTDIR) => {
            permission_denied("worker layout ancestry contains a link or non-directory component")
        }
        _ => error,
    }
}

#[allow(dead_code)] // Opaque authority retained by SetupExecutionContext.
pub(super) struct UserExecutionToken {
    uid: u32,
    gid: u32,
    supplementary_groups: Vec<libc::gid_t>,
    home: OsString,
    name: String,
    requires_drop: bool,
}

#[cfg(test)]
pub(super) fn test_user_execution_token(principal: &WorkerPrincipal) -> UserExecutionToken {
    let account =
        account_details_for_uid(principal.unix_uid().unwrap(), principal.account_policy()).unwrap();
    UserExecutionToken {
        uid: principal.unix_uid().unwrap(),
        gid: account.gid,
        supplementary_groups: current_supplementary_groups().unwrap(),
        home: account.home,
        name: principal.name().to_owned(),
        requires_drop: false,
    }
}

pub(super) fn capture_setup_execution_context() -> io::Result<SetupExecutionContext> {
    let caller = UnixCallerIds::new(
        unsafe { libc::getuid() },
        unsafe { libc::geteuid() },
        unsafe { libc::getgid() },
        unsafe { libc::getegid() },
    );
    let mut original_name = None;
    let selected = super::select_unix_execution(caller, || {
        let (identity, name) = super::parse_sudo_origin_entries(std::env::vars_os())?;
        original_name = Some(name);
        Ok(identity)
    })?;
    let account = account_details_for_uid(selected.uid, WorkerAccountPolicy::CurrentUser)?;
    if account.gid != selected.gid
        || (selected.privilege == SetupHostPrivilege::Root
            && original_name.as_deref() != Some(account.principal.name()))
    {
        return Err(permission_denied(
            "sudo original uid, gid, and account name do not identify one native user",
        ));
    }
    let supplementary_groups = if selected.privilege == SetupHostPrivilege::Root {
        supplementary_groups(account.principal.name(), account.gid)?
    } else {
        current_supplementary_groups()?
    };
    Ok(SetupExecutionContext::new(
        selected.privilege,
        account.principal.clone(),
        UserExecutionToken {
            uid: selected.uid,
            gid: selected.gid,
            supplementary_groups,
            home: account.home,
            name: account.principal.name().to_owned(),
            requires_drop: selected.privilege == SetupHostPrivilege::Root,
        },
    ))
}

pub(super) fn invoke_setup_authorization(
    executable: &Path,
    request_path: &Path,
    request_digest: &str,
) -> io::Result<std::process::ExitStatus> {
    let current = std::env::current_exe()?;
    let executable = super::verify_setup_authorization_executable(executable)?;
    let invocation =
        super::unix_authorization_invocation(&executable, request_path, request_digest, &current)?;
    std::process::Command::new(invocation.program)
        .args(invocation.arguments)
        .status()
}

pub(super) fn verify_setup_authorization_path_security(path: &Path) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| invalid_data("setup authorization path contains a NUL byte"))?;
    let name = c"system.posix_acl_access";
    let size = unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if size > 0 {
        return Err(permission_denied(
            "setup authorization executable path has an extended POSIX ACL",
        ));
    }
    if size == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENODATA | libc::ENOTSUP) => Ok(()),
        _ => Err(error),
    }
}

pub(super) fn run_user_phase(
    token: &UserExecutionToken,
    request: &[u8],
) -> io::Result<std::process::ExitStatus> {
    if request.len() > 64 * 1024 {
        return Err(invalid_data("setup user-phase request is too large"));
    }
    validate_user_execution_token(token)?;
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command.args(["setup", "user-phase"]);
    configure_original_user_command(token, &mut command)?;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native Unix user-phase protocol execution is unavailable in this build",
    ))
}

#[cfg(test)]
pub(super) fn run_test_program_as_original(
    token: &UserExecutionToken,
    program: &Path,
    arguments: &[&str],
) -> io::Result<std::process::Output> {
    let mut command = std::process::Command::new(program);
    command.args(arguments);
    configure_original_user_command(token, &mut command)?;
    command.output()
}

#[allow(dead_code)] // Explicit system-account selection is exercised by environmental gates.
pub(super) fn resolve_named_worker_principal(
    name: &str,
    account_policy: WorkerAccountPolicy,
) -> io::Result<WorkerPrincipal> {
    let uid = lookup_worker_uid(name)?;
    let principal = principal_for_uid(uid, account_policy)?;
    if principal.name() != name {
        return Err(permission_denied(
            "worker account name does not match its native uid",
        ));
    }
    Ok(principal)
}

pub(super) fn verify_worker_principal(principal: &WorkerPrincipal) -> io::Result<()> {
    if principal.principal_kind() != PrincipalKind::UnixUid {
        return Err(invalid_data("worker principal kind does not match Unix"));
    }
    let current = principal_for_uid(principal.unix_uid()?, principal.account_policy())?;
    if &current != principal {
        return Err(permission_denied("worker uid/name identity drift detected"));
    }
    Ok(())
}

pub(super) fn dedicated_account_name_is_valid(name: &str) -> bool {
    name.len() <= 32
}

pub(super) fn inspect_dedicated_account(
    spec: &super::DedicatedAccountSpec,
    home_observation: super::NativeDedicatedAccountInspection,
) -> super::NativeDedicatedAccountObservation {
    let uid = match lookup_worker_uid(spec.name()) {
        Ok(uid) => uid,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return super::NativeDedicatedAccountObservation::Absent;
        }
        Err(_) => return super::NativeDedicatedAccountObservation::Unknowable,
    };
    if uid == 0 {
        return super::NativeDedicatedAccountObservation::PresentBroken;
    }
    let account = match account_details_for_uid(uid, WorkerAccountPolicy::Dedicated) {
        Ok(account) => account,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return super::NativeDedicatedAccountObservation::PresentBroken;
        }
        Err(_) => return super::NativeDedicatedAccountObservation::Unknowable,
    };
    let supplementary_groups = match supplementary_groups(account.principal.name(), account.gid) {
        Ok(groups) => groups,
        Err(_) => return super::NativeDedicatedAccountObservation::Unknowable,
    };
    let primary_group_name = match group_name_for_gid(account.gid) {
        Ok(Some(name)) => name,
        Ok(None) => return super::NativeDedicatedAccountObservation::PresentBroken,
        Err(_) => return super::NativeDedicatedAccountObservation::Unknowable,
    };
    let local_record = match local_account_records_match(&account, &primary_group_name) {
        Ok(true) => LinuxLocalRecordProof::Proven,
        Ok(false) => LinuxLocalRecordProof::MissingOrMismatch,
        Err(_) => LinuxLocalRecordProof::Unknowable,
    };
    let home = PathBuf::from(account.home);
    let home_state = inspect_dedicated_home(&home, uid);
    classify_dedicated_account_record(
        spec,
        LinuxDedicatedAccountRecord {
            principal: account.principal,
            local_record,
            primary_group_name: Some(primary_group_name),
            supplementary_groups: Some(supplementary_groups),
            home,
            shell: PathBuf::from(account.shell),
            home_state,
        },
        home_observation,
    )
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DedicatedHomeState {
    Missing,
    EmptySafe,
    PopulatedSafe,
    Unsafe,
    Unknowable,
}

#[derive(Clone)]
struct LinuxDedicatedAccountRecord {
    principal: WorkerPrincipal,
    local_record: LinuxLocalRecordProof,
    primary_group_name: Option<String>,
    supplementary_groups: Option<Vec<libc::gid_t>>,
    home: PathBuf,
    shell: PathBuf,
    home_state: DedicatedHomeState,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum LinuxLocalRecordProof {
    Proven,
    MissingOrMismatch,
    Unknowable,
}

fn classify_dedicated_account_record(
    spec: &super::DedicatedAccountSpec,
    record: LinuxDedicatedAccountRecord,
    home_observation: super::NativeDedicatedAccountInspection,
) -> super::NativeDedicatedAccountObservation {
    if record.home_state == DedicatedHomeState::Unknowable
        || record.local_record == LinuxLocalRecordProof::Unknowable
        || record.primary_group_name.is_none()
        || record.supplementary_groups.is_none()
    {
        return super::NativeDedicatedAccountObservation::Unknowable;
    }
    let ordinary_uid = record.principal.unix_uid().is_ok_and(|uid| uid >= 1000);
    let home_is_safe = match (home_observation, record.home_state) {
        (_, DedicatedHomeState::EmptySafe)
        | (
            super::NativeDedicatedAccountInspection::Established,
            DedicatedHomeState::PopulatedSafe,
        ) => true,
        (_, DedicatedHomeState::Missing | DedicatedHomeState::Unsafe)
        | (super::NativeDedicatedAccountInspection::Initial, DedicatedHomeState::PopulatedSafe) => {
            false
        }
        (_, DedicatedHomeState::Unknowable) => unreachable!(),
    };
    if record.principal.principal_kind() != PrincipalKind::UnixUid
        || record.principal.account_policy() != WorkerAccountPolicy::Dedicated
        || record.principal.name() != spec.name()
        || !ordinary_uid
        || record.local_record != LinuxLocalRecordProof::Proven
        || record.primary_group_name.as_deref() != Some(spec.name())
        || record
            .supplementary_groups
            .as_ref()
            .is_none_or(|groups| !groups.is_empty())
        || record.home != Path::new("/home").join(spec.name())
        || record.shell != Path::new("/bin/bash")
        || !home_is_safe
    {
        return super::NativeDedicatedAccountObservation::PresentBroken;
    }
    super::NativeDedicatedAccountObservation::PresentHealthy(record.principal)
}

fn inspect_dedicated_home(path: &Path, expected_uid: u32) -> DedicatedHomeState {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return DedicatedHomeState::Missing
        }
        Err(_) => return DedicatedHomeState::Unknowable,
    };
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o022 != 0
    {
        return DedicatedHomeState::Unsafe;
    }
    let directory = match fs::File::open(path) {
        Ok(directory) => directory,
        Err(_) => return DedicatedHomeState::Unknowable,
    };
    match (
        posix_acl_present(&directory, c"system.posix_acl_access"),
        posix_acl_present(&directory, c"system.posix_acl_default"),
    ) {
        (Ok(false), Ok(false)) => {}
        (Ok(true), _) | (_, Ok(true)) => return DedicatedHomeState::Unsafe,
        (Err(_), _) | (_, Err(_)) => return DedicatedHomeState::Unknowable,
    }
    match fs::read_dir(path) {
        Ok(mut entries) => match entries.next() {
            None => DedicatedHomeState::EmptySafe,
            Some(Ok(_)) => DedicatedHomeState::PopulatedSafe,
            Some(Err(_)) => DedicatedHomeState::Unknowable,
        },
        Err(_) => DedicatedHomeState::Unknowable,
    }
}

fn group_name_for_gid(gid: libc::gid_t) -> io::Result<Option<String>> {
    let mut entry = unsafe { std::mem::zeroed::<libc::group>() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];
    let status = unsafe {
        libc::getgrgid_r(
            gid,
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    if result.is_null() {
        return Ok(None);
    }
    if entry.gr_name.is_null() {
        return Err(invalid_data("primary group has no native name"));
    }
    String::from_utf8(
        unsafe { std::ffi::CStr::from_ptr(entry.gr_name) }
            .to_bytes()
            .to_vec(),
    )
    .map(Some)
    .map_err(|_| invalid_data("primary group name is not UTF-8"))
}

fn local_account_records_match(
    account: &UnixAccountDetails,
    primary_group_name: &str,
) -> io::Result<bool> {
    // NSS has no portable provenance API. A healthy Linux observation therefore also requires
    // exact libc-decoded records from the trusted local account databases. Directory-only NSS
    // identities cannot pass; an inaccessible database leaves the observation unknowable.
    let filesystem_root = open_worker_filesystem_root()?;
    local_account_records_match_at(&filesystem_root, 0, c"etc", account, primary_group_name)
}

fn local_account_records_match_at(
    filesystem_root: &std::fs::File,
    expected_owner: libc::uid_t,
    parent_name: &std::ffi::CStr,
    account: &UnixAccountDetails,
    primary_group_name: &str,
) -> io::Result<bool> {
    Ok(
        local_passwd_record_matches_at(filesystem_root, expected_owner, parent_name, account)?
            && local_group_record_matches_at(
                filesystem_root,
                expected_owner,
                parent_name,
                primary_group_name,
                account.gid,
            )?,
    )
}

fn local_passwd_record_matches_at(
    filesystem_root: &std::fs::File,
    expected_owner: libc::uid_t,
    parent_name: &std::ffi::CStr,
    account: &UnixAccountDetails,
) -> io::Result<bool> {
    let Some(stream) =
        open_local_account_database_at(filesystem_root, expected_owner, parent_name, c"passwd")?
    else {
        return Ok(false);
    };
    let expected_uid = account.principal.unix_uid()?;
    let expected_name = account.principal.name().as_bytes();
    let mut found = false;
    loop {
        let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_u8; 64 * 1024];
        let status = unsafe {
            libc::fgetpwent_r(
                stream.0,
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        match classify_local_account_scan_step(
            status,
            result.is_null(),
            unsafe { libc::feof(stream.0) } != 0,
            unsafe { libc::ferror(stream.0) } != 0,
            found,
        )? {
            LocalAccountScanStep::Record => {}
            LocalAccountScanStep::Complete(found) => return Ok(found),
        }
        if entry.pw_name.is_null() || entry.pw_dir.is_null() || entry.pw_shell.is_null() {
            return Err(invalid_data("local passwd record is incomplete"));
        }
        let name = unsafe { std::ffi::CStr::from_ptr(entry.pw_name) }.to_bytes();
        if name != expected_name && entry.pw_uid != expected_uid {
            continue;
        }
        let home = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) }.to_bytes();
        let shell = unsafe { std::ffi::CStr::from_ptr(entry.pw_shell) }.to_bytes();
        if found
            || name != expected_name
            || entry.pw_uid != expected_uid
            || entry.pw_gid != account.gid
            || home != account.home.as_os_str().as_bytes()
            || shell != account.shell.as_os_str().as_bytes()
        {
            return Ok(false);
        }
        found = true;
    }
}

fn local_group_record_matches_at(
    filesystem_root: &std::fs::File,
    expected_owner: libc::uid_t,
    parent_name: &std::ffi::CStr,
    expected_name: &str,
    expected_gid: libc::gid_t,
) -> io::Result<bool> {
    let Some(stream) =
        open_local_account_database_at(filesystem_root, expected_owner, parent_name, c"group")?
    else {
        return Ok(false);
    };
    let mut found = false;
    loop {
        let mut entry = unsafe { std::mem::zeroed::<libc::group>() };
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_u8; 64 * 1024];
        let status = unsafe {
            libc::fgetgrent_r(
                stream.0,
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        match classify_local_account_scan_step(
            status,
            result.is_null(),
            unsafe { libc::feof(stream.0) } != 0,
            unsafe { libc::ferror(stream.0) } != 0,
            found,
        )? {
            LocalAccountScanStep::Record => {}
            LocalAccountScanStep::Complete(found) => return Ok(found),
        }
        if entry.gr_name.is_null() {
            return Err(invalid_data("local group record is incomplete"));
        }
        let name = unsafe { std::ffi::CStr::from_ptr(entry.gr_name) }.to_bytes();
        if name != expected_name.as_bytes() && entry.gr_gid != expected_gid {
            continue;
        }
        if found || name != expected_name.as_bytes() || entry.gr_gid != expected_gid {
            return Ok(false);
        }
        // `gr_mem` lists other explicit members; it does not grant this worker another group.
        // The worker's effective NSS group set is separately required to contain no distinct GID.
        found = true;
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum LocalAccountScanStep {
    Record,
    Complete(bool),
}

fn classify_local_account_scan_step(
    status: libc::c_int,
    result_is_null: bool,
    stream_eof: bool,
    stream_error: bool,
    found: bool,
) -> io::Result<LocalAccountScanStep> {
    if result_is_null && stream_eof && !stream_error && matches!(status, 0 | libc::ENOENT) {
        return Ok(LocalAccountScanStep::Complete(found));
    }
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    if stream_error {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    if result_is_null || stream_eof {
        return Err(invalid_data(
            "local account database scan returned inconsistent state",
        ));
    }
    Ok(LocalAccountScanStep::Record)
}

#[derive(Clone, Copy)]
struct LocalAccountDatabaseNode {
    mode: libc::mode_t,
    uid: libc::uid_t,
    identity: PrivateFileIdentity,
}

fn local_account_database_root_is_trusted(
    root: LocalAccountDatabaseNode,
    expected_owner: libc::uid_t,
    access_acl: bool,
    default_acl: bool,
) -> bool {
    root.mode & libc::S_IFMT == libc::S_IFDIR
        && root.uid == expected_owner
        && root.mode & 0o022 == 0
        && !access_acl
        && !default_acl
}

fn local_account_database_directory_is_trusted(
    opened: LocalAccountDatabaseNode,
    named: LocalAccountDatabaseNode,
    expected_owner: libc::uid_t,
    access_acl: bool,
    default_acl: bool,
) -> bool {
    opened.mode & libc::S_IFMT == libc::S_IFDIR
        && named.mode & libc::S_IFMT == libc::S_IFDIR
        && opened.uid == expected_owner
        && named.uid == expected_owner
        && opened.mode & 0o022 == 0
        && named.mode & 0o022 == 0
        && opened.identity == named.identity
        && !access_acl
        && !default_acl
}

fn local_account_database_file_is_trusted(
    opened: LocalAccountDatabaseNode,
    named: LocalAccountDatabaseNode,
    expected_owner: libc::uid_t,
    access_acl: bool,
) -> bool {
    opened.mode & libc::S_IFMT == libc::S_IFREG
        && named.mode & libc::S_IFMT == libc::S_IFREG
        && opened.uid == expected_owner
        && named.uid == expected_owner
        && opened.mode & 0o022 == 0
        && named.mode & 0o022 == 0
        && opened.identity == named.identity
        && !access_acl
}

fn local_account_database_node(file: &std::fs::File) -> io::Result<LocalAccountDatabaseNode> {
    let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut status) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(local_account_database_node_from_status(&status))
}

fn local_account_database_named_node(
    parent: &std::fs::File,
    name: &std::ffi::CStr,
) -> io::Result<Option<LocalAccountDatabaseNode>> {
    let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut status,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == -1
    {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP) => Ok(None),
            _ => Err(error),
        };
    }
    Ok(Some(local_account_database_node_from_status(&status)))
}

fn local_account_database_node_from_status(status: &libc::stat) -> LocalAccountDatabaseNode {
    LocalAccountDatabaseNode {
        mode: status.st_mode,
        uid: status.st_uid,
        identity: PrivateFileIdentity::new(status.st_dev, status.st_ino),
    }
}

fn open_local_account_node_at(
    parent: &std::fs::File,
    name: &std::ffi::CStr,
    flags: libc::c_int,
) -> io::Result<Option<std::fs::File>> {
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if descriptor == -1 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP) => Ok(None),
            _ => Err(error),
        };
    }
    Ok(Some(unsafe { std::fs::File::from_raw_fd(descriptor) }))
}

fn open_local_account_database_at(
    filesystem_root: &std::fs::File,
    expected_owner: libc::uid_t,
    parent_name: &std::ffi::CStr,
    name: &std::ffi::CStr,
) -> io::Result<Option<OwnedFileStream>> {
    let root = local_account_database_node(filesystem_root)?;
    let access_acl = posix_acl_present(filesystem_root, c"system.posix_acl_access")?;
    let default_acl = posix_acl_present(filesystem_root, c"system.posix_acl_default")?;
    if !local_account_database_root_is_trusted(root, expected_owner, access_acl, default_acl) {
        return Ok(None);
    }
    let Some(parent) = open_local_account_node_at(
        filesystem_root,
        parent_name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )?
    else {
        return Ok(None);
    };
    let opened_parent = local_account_database_node(&parent)?;
    let Some(named_parent) = local_account_database_named_node(filesystem_root, parent_name)?
    else {
        return Ok(None);
    };
    let access_acl = posix_acl_present(&parent, c"system.posix_acl_access")?;
    let default_acl = posix_acl_present(&parent, c"system.posix_acl_default")?;
    if !local_account_database_directory_is_trusted(
        opened_parent,
        named_parent,
        expected_owner,
        access_acl,
        default_acl,
    ) {
        return Ok(None);
    }

    let Some(file) = open_local_account_node_at(
        &parent,
        name,
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )?
    else {
        return Ok(None);
    };
    let opened_file = local_account_database_node(&file)?;
    let Some(named_file) = local_account_database_named_node(&parent, name)? else {
        return Ok(None);
    };
    let access_acl = posix_acl_present(&file, c"system.posix_acl_access")?;
    if !local_account_database_file_is_trusted(opened_file, named_file, expected_owner, access_acl)
    {
        return Ok(None);
    }

    let descriptor = file.into_raw_fd();
    let stream = unsafe { libc::fdopen(descriptor, c"r".as_ptr()) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(descriptor);
        }
        return Err(error);
    }
    Ok(Some(OwnedFileStream(stream)))
}

struct OwnedFileStream(*mut libc::FILE);

impl Drop for OwnedFileStream {
    fn drop(&mut self) {
        unsafe {
            libc::fclose(self.0);
        }
    }
}

fn principal_for_uid(uid: u32, account_policy: WorkerAccountPolicy) -> io::Result<WorkerPrincipal> {
    account_for_uid(uid, account_policy).map(|(principal, _)| principal)
}

fn account_for_uid(
    uid: u32,
    account_policy: WorkerAccountPolicy,
) -> io::Result<(WorkerPrincipal, u32)> {
    let account = account_details_for_uid(uid, account_policy)?;
    Ok((account.principal, account.gid))
}

struct UnixAccountDetails {
    principal: WorkerPrincipal,
    gid: u32,
    home: OsString,
    shell: OsString,
}

fn account_details_for_uid(
    uid: u32,
    account_policy: WorkerAccountPolicy,
) -> io::Result<UnixAccountDetails> {
    if uid == 0 {
        return Err(permission_denied("root cannot be a worker principal"));
    }
    let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    if result.is_null()
        || entry.pw_name.is_null()
        || entry.pw_dir.is_null()
        || entry.pw_shell.is_null()
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "worker uid has no native account mapping",
        ));
    }
    let name = unsafe { std::ffi::CStr::from_ptr(entry.pw_name) }
        .to_str()
        .map_err(|_| invalid_data("worker account name is not UTF-8"))?;
    let home = OsString::from_vec(
        unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) }
            .to_bytes()
            .to_vec(),
    );
    let shell = OsString::from_vec(
        unsafe { std::ffi::CStr::from_ptr(entry.pw_shell) }
            .to_bytes()
            .to_vec(),
    );
    if !Path::new(&home).is_absolute() {
        return Err(invalid_data("worker home directory is not absolute"));
    }
    Ok(UnixAccountDetails {
        principal: WorkerPrincipal::new(
            PrincipalKind::UnixUid,
            uid.to_string(),
            name,
            account_policy,
        )?,
        gid: entry.pw_gid,
        home,
        shell,
    })
}

fn supplementary_groups(name: &str, primary_gid: u32) -> io::Result<Vec<libc::gid_t>> {
    let name = CString::new(name).map_err(|_| invalid_data("worker account name contains NUL"))?;
    let mut count = 16;
    let mut groups = vec![0; count as usize];
    if unsafe { libc::getgrouplist(name.as_ptr(), primary_gid, groups.as_mut_ptr(), &mut count) }
        == -1
    {
        if !(17..=1024).contains(&count) {
            return Err(permission_denied(
                "worker supplementary group set is invalid",
            ));
        }
        groups.resize(count as usize, 0);
        if unsafe {
            libc::getgrouplist(name.as_ptr(), primary_gid, groups.as_mut_ptr(), &mut count)
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
    }
    if !(1..=1024).contains(&count) {
        return Err(permission_denied(
            "worker supplementary group set is invalid",
        ));
    }
    groups.truncate(count as usize);
    groups.retain(|group| *group != primary_gid);
    groups.sort_unstable();
    groups.dedup();
    Ok(groups)
}

fn current_supplementary_groups() -> io::Result<Vec<libc::gid_t>> {
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if !(0..=1024).contains(&count) {
        return Err(permission_denied(
            "current supplementary group set is invalid",
        ));
    }
    let mut groups = vec![0; count as usize];
    if count != 0 && unsafe { libc::getgroups(count, groups.as_mut_ptr()) } != count {
        return Err(io::Error::last_os_error());
    }
    groups.sort_unstable();
    groups.dedup();
    Ok(groups)
}

fn validate_user_execution_token(token: &UserExecutionToken) -> io::Result<()> {
    if token.uid == 0
        || token.name.is_empty()
        || !Path::new(&token.home).is_absolute()
        || token.supplementary_groups.len() > 1024
    {
        return Err(permission_denied(
            "original-user execution token is invalid",
        ));
    }
    Ok(())
}

fn configure_original_user_command(
    token: &UserExecutionToken,
    command: &mut std::process::Command,
) -> io::Result<()> {
    validate_user_execution_token(token)?;
    command.env_clear();
    command.env("HOME", &token.home);
    command.env("USER", &token.name);
    command.env("LOGNAME", &token.name);
    command.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");
    command.current_dir(&token.home);
    let uid = token.uid;
    let gid = token.gid;
    let groups = token.supplementary_groups.clone();
    let requires_drop = token.requires_drop;
    let mut observed_groups = vec![0; 1024];
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if requires_drop
                && (libc::setgroups(groups.len(), groups.as_ptr()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0)
            {
                return Err(io::Error::last_os_error());
            }
            if libc::getuid() != uid
                || libc::geteuid() != uid
                || libc::getgid() != gid
                || libc::getegid() != gid
            {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            let group_count = libc::getgroups(1024, observed_groups.as_mut_ptr());
            if group_count < 0 {
                return Err(io::Error::last_os_error());
            }
            let observed = &mut observed_groups[..group_count as usize];
            observed.sort_unstable();
            if observed != groups.as_slice() {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            if requires_drop && libc::seteuid(0) == 0 {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(())
        });
    }
    Ok(())
}

pub(super) fn create_private_manifest_staging_directory(
    path: &Path,
    _owner: ManifestOwner,
    _principal: &WorkerPrincipal,
) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

pub(super) fn harden_manifest_directory(
    path: &Path,
    owner: ManifestOwner,
    _worker: &WorkerPrincipal,
) -> io::Result<()> {
    require_real_directory(path)?;
    apply_owner(path, owner)?;
    let mode = if matches!(owner, ManifestOwner::User) {
        0o700
    } else {
        0o755
    };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    verify_directory(path, owner, _worker)
}

pub(super) fn harden_manifest_file(
    path: &Path,
    owner: ManifestOwner,
    _worker: &WorkerPrincipal,
) -> io::Result<()> {
    require_regular_file(path)?;
    apply_owner(path, owner)?;
    let mode = if matches!(owner, ManifestOwner::User) {
        0o600
    } else {
        0o644
    };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    verify_file(path, owner, _worker, mode, "manifest")
}

pub(super) fn open_manifest_lock(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> io::Result<fs::File> {
    let created = create_private_file(path, owner, principal);
    let file = match created {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            verify_private_file_security(path, owner, principal)?;
            fs::OpenOptions::new().read(true).write(true).open(path)?
        }
        Err(error) => return Err(error),
    };
    verify_private_file_security(path, owner, principal)?;
    Ok(file)
}

pub(super) fn verify_private_file_security(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> io::Result<()> {
    verify_file(path, owner, principal, 0o600, "private store file")
}

pub(super) fn create_private_file(
    path: &Path,
    _owner: ManifestOwner,
    _principal: &WorkerPrincipal,
) -> io::Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    clear_posix_acl(&file, c"system.posix_acl_access")?;
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

#[allow(dead_code)] // Reached by the controller identity consumer on native Linux.
pub(super) fn lock_controller_identity_file(file: &fs::File) -> io::Result<()> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn private_file_identity(path: &Path) -> io::Result<PrivateFileIdentity> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(permission_denied(
            "private store target is not a regular file",
        ));
    }
    Ok(PrivateFileIdentity::new(metadata.dev(), metadata.ino()))
}

#[allow(dead_code)] // Consumed through the deferred T0.13 publication adapter.
pub(super) fn private_file_identity_from_handle(
    file: &std::fs::File,
) -> io::Result<PrivateFileIdentity> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(permission_denied(
            "private publication handle is not a regular file",
        ));
    }
    Ok(PrivateFileIdentity::new(metadata.dev(), metadata.ino()))
}

#[allow(dead_code)] // Consumed through the deferred T0.13 publication adapter.
pub(super) fn verify_private_file_handle_security(
    file: &std::fs::File,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(permission_denied(
            "private publication handle is not a regular file",
        ));
    }
    let expected_uid = match owner {
        ManifestOwner::System => 0,
        ManifestOwner::User => principal.unix_uid()?,
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => metadata.uid(),
    };
    if metadata.uid() != expected_uid || metadata.mode() & 0o777 != 0o600 {
        return Err(permission_denied(
            "private publication handle ownership or mode is insecure",
        ));
    }
    if posix_acl_present(file, c"system.posix_acl_access")? {
        return Err(permission_denied(
            "private publication handle has an access ACL",
        ));
    }
    Ok(())
}

#[allow(dead_code)] // Consumed through the deferred T0.13 publication adapter.
pub(super) fn publish_private_file_no_replace(
    file: &std::fs::File,
    temporary: &Path,
    destination: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    expected_identity: PrivateFileIdentity,
) -> io::Result<()> {
    if private_file_identity_from_handle(file)? != expected_identity {
        return Err(permission_denied(
            "private publication handle identity changed",
        ));
    }
    drop(open_verified_private_file_for_read(
        temporary,
        owner,
        principal,
        expected_identity,
    )?);
    std::fs::hard_link(temporary, destination)?;
    let parent = destination
        .parent()
        .ok_or_else(|| invalid_data("private publication destination has no parent"))?;
    std::fs::File::open(parent)?.sync_all()?;
    drop(open_verified_private_file_for_read(
        destination,
        owner,
        principal,
        expected_identity,
    )?);
    let removal =
        prepare_verified_private_file_removal(temporary, owner, principal, expected_identity)?;
    consume_verified_private_file(removal)?;
    std::fs::File::open(parent)?.sync_all()
}

pub(super) fn open_verified_private_file_for_read(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    expected_identity: PrivateFileIdentity,
) -> io::Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || PrivateFileIdentity::new(metadata.dev(), metadata.ino()) != expected_identity
    {
        return Err(permission_denied(
            "private store target identity or type changed",
        ));
    }
    let expected_uid = match owner {
        ManifestOwner::System => 0,
        ManifestOwner::User => principal.unix_uid()?,
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => metadata.uid(),
    };
    if metadata.uid() != expected_uid || metadata.mode() & 0o777 != 0o600 {
        return Err(permission_denied(
            "private store file ownership or mode is insecure",
        ));
    }
    Ok(file)
}

pub(crate) struct PrivateFileRemoval {
    parent: fs::File,
    leaf: CString,
    expected_identity: PrivateFileIdentity,
}

pub(super) fn prepare_verified_private_file_removal(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    expected_identity: PrivateFileIdentity,
) -> io::Result<PrivateFileRemoval> {
    let parent_path = path
        .parent()
        .ok_or_else(|| invalid_data("private file has no parent directory"))?;
    let leaf = path
        .file_name()
        .ok_or_else(|| invalid_data("private file has no leaf name"))?;
    let leaf = CString::new(leaf.as_bytes())
        .map_err(|_| invalid_data("private file leaf contains a NUL byte"))?;
    let parent = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent_path)?;
    let parent_metadata = parent.metadata()?;
    let expected_uid = match owner {
        ManifestOwner::System => 0,
        ManifestOwner::User => principal.unix_uid()?,
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => unsafe {
            libc::geteuid()
        },
    };
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != expected_uid
        || !super::private_file_parent_mode_is_valid(owner, parent_metadata.mode())
    {
        return Err(permission_denied(
            "private file parent ownership or mode is insecure",
        ));
    }
    verify_private_file_at(parent.as_raw_fd(), &leaf, expected_uid, expected_identity)?;
    Ok(PrivateFileRemoval {
        parent,
        leaf,
        expected_identity,
    })
}

pub(super) fn consume_verified_private_file(removal: PrivateFileRemoval) -> io::Result<()> {
    let parent = removal.parent.as_raw_fd();
    let expected_uid = unsafe {
        let mut stat = std::mem::zeroed::<libc::stat>();
        if libc::fstatat(
            parent,
            removal.leaf.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        ) == -1
        {
            return Err(io::Error::last_os_error());
        }
        stat.st_uid
    };
    verify_private_file_at(
        parent,
        &removal.leaf,
        expected_uid,
        removal.expected_identity,
    )?;
    let tombstone = CString::new(format!(".styrn-consumed-{}", uuid::Uuid::now_v7()))
        .expect("UUID tombstone names contain no NUL bytes");
    if unsafe {
        libc::renameat2(
            parent,
            removal.leaf.as_ptr(),
            parent,
            tombstone.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    verify_private_file_at(parent, &tombstone, expected_uid, removal.expected_identity)?;
    if unsafe { libc::unlinkat(parent, tombstone.as_ptr(), 0) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn verify_private_file_at(
    parent: libc::c_int,
    leaf: &CString,
    expected_uid: u32,
    expected_identity: PrivateFileIdentity,
) -> io::Result<()> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstatat(parent, leaf.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } == -1 {
        return Err(io::Error::last_os_error());
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || PrivateFileIdentity::new(stat.st_dev as u64, stat.st_ino as u64) != expected_identity
        || stat.st_uid != expected_uid
        || stat.st_mode & 0o777 != 0o600
    {
        return Err(permission_denied(
            "private file identity, ownership, or mode changed before consumption",
        ));
    }
    Ok(())
}

pub(super) fn verify_manifest_security(
    path: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
    trusted_root: &Path,
) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("manifest path has no parent directory"))?;
    require_real_directory(parent)?;
    require_regular_file(path)?;
    let file = fs::metadata(path)?;
    let directory = fs::metadata(parent)?;
    let expected_uid = match owner {
        ManifestOwner::System => 0,
        ManifestOwner::User => worker.unix_uid()?,
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => file.uid(),
    };
    validate_store_inspection(
        owner,
        &UnixManifestInspection {
            expected_uid,
            file_uid: file.uid(),
            file_mode: file.mode() & 0o777,
            directory_uid: directory.uid(),
            directory_mode: directory.mode() & 0o777,
        },
    )?;
    verify_manifest_ancestors(parent, owner, worker, trusted_root)
}

#[allow(dead_code)] // Source-including manifest tests do not include receipt reads.
pub(super) fn open_verified_manifest_file_for_read(
    path: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
    trusted_root: &Path,
) -> io::Result<fs::File> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("manifest path has no parent directory"))?;
    require_real_directory(parent)?;
    verify_manifest_ancestors(parent, owner, worker, trusted_root)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let file_metadata = file.metadata()?;
    if !file_metadata.is_file() {
        return Err(permission_denied("manifest target is not a regular file"));
    }
    let directory = fs::metadata(parent)?;
    let expected_uid = match owner {
        ManifestOwner::System => 0,
        ManifestOwner::User => worker.unix_uid()?,
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => file_metadata.uid(),
    };
    validate_store_inspection(
        owner,
        &UnixManifestInspection {
            expected_uid,
            file_uid: file_metadata.uid(),
            file_mode: file_metadata.mode() & 0o777,
            directory_uid: directory.uid(),
            directory_mode: directory.mode() & 0o777,
        },
    )?;
    verify_manifest_ancestors(parent, owner, worker, trusted_root)?;
    Ok(file)
}

pub(super) fn verify_manifest_file_target(path: &Path) -> io::Result<()> {
    require_regular_file(path)
}

pub(super) fn verify_manifest_directory_security(
    directory: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
) -> io::Result<()> {
    verify_directory(directory, owner, worker)
}

pub(super) fn publish_manifest_directory(staging: &Path, destination: &Path) -> io::Result<()> {
    require_real_directory(staging)?;
    let staging = std::ffi::CString::new(staging.as_os_str().as_bytes())
        .map_err(|_| invalid_data("manifest staging path contains a NUL byte"))?;
    let destination = std::ffi::CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| invalid_data("manifest destination path contains a NUL byte"))?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            staging.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } == -1
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn verify_manifest_parent_chain(
    parent: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
) -> io::Result<()> {
    if matches!(owner, ManifestOwner::User) {
        return verify_user_trusted_root_chain(parent, worker.unix_uid()?);
    }
    require_real_directory(parent)?;
    let worker_uid = worker_uid(owner, worker)?;
    let child_uid = match owner {
        ManifestOwner::System => 0,
        ManifestOwner::User => unsafe { libc::geteuid() },
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => unsafe {
            libc::geteuid()
        },
    };
    verify_ancestor_chain(parent, child_uid, owner, worker_uid)
}

pub(super) fn verify_manifest_ancestors(
    directory: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
    trusted_root: &Path,
) -> io::Result<()> {
    let system_owner = matches!(owner, ManifestOwner::System);
    if (system_owner && directory != trusted_root)
        || (!system_owner && !directory.starts_with(trusted_root))
    {
        return Err(permission_denied(
            "manifest directory is outside its trusted root",
        ));
    }
    if matches!(owner, ManifestOwner::User) {
        return verify_user_manifest_ancestors(directory, trusted_root, worker.unix_uid()?);
    }
    if !system_owner && directory == trusted_root {
        return require_real_directory(directory);
    }
    require_real_directory(directory)?;
    let worker_uid = worker_uid(owner, worker)?;
    let mut child_uid = fs::symlink_metadata(directory)?.uid();
    let mut current = directory.parent();
    while let Some(ancestor) = current {
        require_real_directory(ancestor)?;
        let metadata = fs::metadata(ancestor)?;
        let mode = metadata.mode();
        validate_ancestor_access(metadata.uid(), mode, worker_uid, system_owner)?;
        if mode & 0o022 != 0 {
            let safe_sticky_root = matches!(owner, ManifestOwner::System)
                && mode & 0o1000 != 0
                && metadata.uid() == 0
                && child_uid == 0;
            if !safe_sticky_root {
                return Err(permission_denied(
                    "manifest ancestor grants replacement access",
                ));
            }
        }
        child_uid = metadata.uid();
        if !system_owner && ancestor == trusted_root {
            return Ok(());
        }
        current = ancestor.parent();
    }
    if system_owner {
        Ok(())
    } else {
        Err(permission_denied(
            "manifest trusted root is not an ancestor",
        ))
    }
}

fn verify_user_manifest_ancestors(
    directory: &Path,
    trusted_root: &Path,
    current_uid: u32,
) -> io::Result<()> {
    require_real_directory(directory)?;
    if directory != trusted_root {
        let mut current = directory.parent();
        while let Some(ancestor) = current {
            if ancestor == trusted_root {
                break;
            }
            require_real_directory(ancestor)?;
            let metadata = fs::metadata(ancestor)?;
            if metadata.uid() != current_uid || metadata.mode() & 0o022 != 0 {
                return Err(permission_denied(
                    "user state directory owner or write permissions are insecure",
                ));
            }
            current = ancestor.parent();
        }
        if current.is_none() {
            return Err(permission_denied(
                "manifest trusted root is not an ancestor",
            ));
        }
    }
    verify_user_trusted_root_chain(trusted_root, current_uid)
}

fn verify_user_trusted_root_chain(path: &Path, current_uid: u32) -> io::Result<()> {
    require_real_directory(path)?;
    let metadata = fs::metadata(path)?;
    if metadata.uid() != current_uid || metadata.mode() & 0o022 != 0 {
        return Err(permission_denied(
            "user state root owner or write permissions are insecure",
        ));
    }
    let mut child_uid = metadata.uid();
    let mut reached_system_owner = false;
    let mut current = path.parent();
    while let Some(ancestor) = current {
        require_real_directory(ancestor)?;
        let metadata = fs::metadata(ancestor)?;
        validate_user_ancestor_access(
            metadata.uid(),
            metadata.mode(),
            child_uid,
            current_uid,
            &mut reached_system_owner,
        )?;
        child_uid = metadata.uid();
        current = ancestor.parent();
    }
    Ok(())
}

fn validate_user_ancestor_access(
    uid: u32,
    mode: u32,
    child_uid: u32,
    current_uid: u32,
    reached_system_owner: &mut bool,
) -> io::Result<()> {
    if uid == 0 {
        *reached_system_owner = true;
    } else if uid != current_uid || *reached_system_owner {
        return Err(permission_denied(
            "user state ancestor has an unrelated or invalid owner transition",
        ));
    }
    if mode & 0o022 != 0 {
        let trusted_owner = uid == 0 || uid == current_uid;
        let sticky_protects_user_child =
            mode & 0o1000 != 0 && child_uid == current_uid && trusted_owner;
        if !sticky_protects_user_child {
            return Err(permission_denied(
                "user state ancestor grants unrelated replacement access",
            ));
        }
    }
    Ok(())
}

fn verify_ancestor_chain(
    start: &Path,
    mut child_uid: u32,
    owner: ManifestOwner,
    worker_uid: Option<u32>,
) -> io::Result<()> {
    let system_owner = matches!(owner, ManifestOwner::System);
    let mut current = Some(start);
    while let Some(ancestor) = current {
        require_real_directory(ancestor)?;
        let metadata = fs::metadata(ancestor)?;
        let mode = metadata.mode();
        validate_ancestor_access(metadata.uid(), mode, worker_uid, system_owner)?;
        if mode & 0o022 != 0 {
            let safe_sticky_root =
                system_owner && mode & 0o1000 != 0 && metadata.uid() == 0 && child_uid == 0;
            if !safe_sticky_root {
                return Err(permission_denied(
                    "manifest ancestor grants replacement access",
                ));
            }
        }
        child_uid = metadata.uid();
        current = ancestor.parent();
    }
    Ok(())
}

fn worker_uid(owner: ManifestOwner, worker: &WorkerPrincipal) -> io::Result<Option<u32>> {
    match owner {
        ManifestOwner::System => Ok(Some(worker.unix_uid()?)),
        ManifestOwner::User => Ok(None),
        #[cfg(test)]
        ManifestOwner::CurrentProcess => Ok(None),
        #[cfg(test)]
        ManifestOwner::CurrentProcessWorker => Ok(Some(unsafe { libc::geteuid() })),
    }
}

fn validate_ancestor_access(
    uid: u32,
    mode: u32,
    worker_uid: Option<u32>,
    require_worker_traversal: bool,
) -> io::Result<()> {
    if require_worker_traversal && mode & 0o001 == 0 {
        return Err(permission_denied(
            "manifest ancestor is not traversable by the configured worker",
        ));
    }
    if worker_uid == Some(uid) {
        return Err(permission_denied(
            "configured worker owns a manifest ancestor",
        ));
    }
    Ok(())
}

#[allow(dead_code)] // Called by the environmental selected-account gate.
fn lookup_worker_uid(worker: &str) -> io::Result<u32> {
    let worker = std::ffi::CString::new(worker)
        .map_err(|_| invalid_data("worker account contains a NUL byte"))?;
    let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];
    let status = unsafe {
        libc::getpwnam_r(
            worker.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    if result.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "configured worker account is unavailable",
        ));
    }
    Ok(entry.pw_uid)
}

#[derive(Clone, Copy)]
struct UnixManifestInspection {
    expected_uid: u32,
    file_uid: u32,
    file_mode: u32,
    directory_uid: u32,
    directory_mode: u32,
}

fn validate_manifest_inspection(inspection: &UnixManifestInspection) -> io::Result<()> {
    if inspection.file_uid != inspection.expected_uid
        || inspection.directory_uid != inspection.expected_uid
    {
        return Err(permission_denied(
            "manifest file and directory owner mismatch",
        ));
    }
    if inspection.file_mode != 0o644 {
        return Err(permission_denied("manifest mode must be 0644"));
    }
    if inspection.directory_mode != 0o755 {
        return Err(permission_denied("manifest directory mode must be 0755"));
    }
    Ok(())
}

fn validate_store_inspection(
    owner: ManifestOwner,
    inspection: &UnixManifestInspection,
) -> io::Result<()> {
    if !matches!(owner, ManifestOwner::User) {
        return validate_manifest_inspection(inspection);
    }
    if inspection.file_uid != inspection.expected_uid
        || inspection.directory_uid != inspection.expected_uid
    {
        return Err(permission_denied(
            "user state file and directory owner mismatch",
        ));
    }
    if inspection.file_mode != 0o600 || inspection.directory_mode != 0o700 {
        return Err(permission_denied(
            "user state requires file mode 0600 and directory mode 0700",
        ));
    }
    Ok(())
}

fn apply_owner(path: &Path, owner: ManifestOwner) -> io::Result<()> {
    match owner {
        ManifestOwner::System => std::os::unix::fs::chown(path, Some(0), Some(0)),
        ManifestOwner::User => Ok(()),
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => Ok(()),
    }
}

fn verify_directory(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> io::Result<()> {
    require_real_directory(path)?;
    let metadata = fs::metadata(path)?;
    verify_owner(&metadata, owner, principal, "manifest directory")?;
    let expected_mode = if matches!(owner, ManifestOwner::User) {
        0o700
    } else {
        0o755
    };
    if metadata.mode() & 0o777 != expected_mode {
        return Err(permission_denied(&format!(
            "manifest directory mode must be {expected_mode:04o}"
        )));
    }
    Ok(())
}

fn verify_file(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    mode: u32,
    label: &str,
) -> io::Result<()> {
    require_regular_file(path)?;
    let metadata = fs::metadata(path)?;
    verify_owner(&metadata, owner, principal, label)?;
    if metadata.mode() & 0o777 != mode {
        return Err(permission_denied(&format!(
            "{label} mode must be {mode:04o}, found {:04o}",
            metadata.mode() & 0o777
        )));
    }
    Ok(())
}

fn verify_owner(
    metadata: &fs::Metadata,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    label: &str,
) -> io::Result<()> {
    let expected = match owner {
        ManifestOwner::System => 0,
        ManifestOwner::User => principal.unix_uid()?,
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => metadata.uid(),
    };
    if metadata.uid() != expected {
        return Err(permission_denied(&format!(
            "{label} owner must be uid {expected}, found {}",
            metadata.uid()
        )));
    }
    Ok(())
}

fn require_regular_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(invalid_data(
            "manifest security target is not a regular file",
        ));
    }
    Ok(())
}

fn require_real_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(invalid_data(
            "manifest security target is not a real directory",
        ));
    }
    Ok(())
}

fn permission_denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.to_owned())
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedicated_account_spec_applies_linux_name_rules() {
        for valid in ["build-agent", "ci_worker", "worker7"] {
            assert!(super::super::DedicatedAccountSpec::new(valid).is_ok());
        }
        let oversized = "a".repeat(33);
        let error = match super::super::DedicatedAccountSpec::new(&oversized) {
            Ok(_) => panic!("Linux-invalid dedicated account name was accepted"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            super::super::DEDICATED_ACCOUNT_NAME_ERROR
        );
    }

    fn healthy_dedicated_account_record() -> LinuxDedicatedAccountRecord {
        LinuxDedicatedAccountRecord {
            principal: WorkerPrincipal::new(
                PrincipalKind::UnixUid,
                "1001",
                "build-agent",
                WorkerAccountPolicy::Dedicated,
            )
            .unwrap(),
            local_record: LinuxLocalRecordProof::Proven,
            primary_group_name: Some("build-agent".to_owned()),
            supplementary_groups: Some(Vec::new()),
            home: PathBuf::from("/home/build-agent"),
            shell: PathBuf::from("/bin/bash"),
            home_state: DedicatedHomeState::EmptySafe,
        }
    }

    fn assert_dedicated_account_broken(record: LinuxDedicatedAccountRecord) {
        let spec = super::super::DedicatedAccountSpec::new("build-agent").unwrap();
        assert!(matches!(
            classify_dedicated_account_record(
                &spec,
                record,
                super::super::NativeDedicatedAccountInspection::Initial,
            ),
            super::super::NativeDedicatedAccountObservation::PresentBroken,
        ));
    }

    #[test]
    fn dedicated_account_observation_never_treats_nss_alone_as_local_provenance() {
        let spec = super::super::DedicatedAccountSpec::new("build-agent").unwrap();
        let mut record = healthy_dedicated_account_record();
        record.local_record = LinuxLocalRecordProof::MissingOrMismatch;
        assert!(matches!(
            classify_dedicated_account_record(
                &spec,
                record,
                super::super::NativeDedicatedAccountInspection::Initial,
            ),
            super::super::NativeDedicatedAccountObservation::PresentBroken,
        ));
    }

    #[test]
    fn local_account_scan_treats_glibc_enoent_with_null_result_as_eof() {
        assert!(matches!(
            classify_local_account_scan_step(libc::ENOENT, true, true, false, true).unwrap(),
            LocalAccountScanStep::Complete(true)
        ));
        assert!(matches!(
            classify_local_account_scan_step(libc::ENOENT, true, true, false, false).unwrap(),
            LocalAccountScanStep::Complete(false)
        ));
    }

    #[test]
    fn local_account_scan_requires_clean_eof_and_propagates_other_errors() {
        for result in [
            classify_local_account_scan_step(libc::ENOENT, true, false, false, false),
            classify_local_account_scan_step(libc::ENOENT, true, true, true, false),
            classify_local_account_scan_step(libc::ENOENT, false, false, false, false),
        ] {
            assert!(result.is_err());
        }
        let error = match classify_local_account_scan_step(libc::EIO, true, false, true, false) {
            Ok(_) => panic!("a stream error was accepted as scan completion"),
            Err(error) => error,
        };
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    }

    fn trusted_local_account_database_node(file_type: libc::mode_t) -> LocalAccountDatabaseNode {
        LocalAccountDatabaseNode {
            mode: file_type | 0o644,
            uid: 0,
            identity: PrivateFileIdentity::new(41, 73),
        }
    }

    #[test]
    fn local_account_database_parent_rejects_access_and_default_acls() {
        let mut parent = trusted_local_account_database_node(libc::S_IFDIR);
        parent.mode = libc::S_IFDIR | 0o755;
        assert!(local_account_database_directory_is_trusted(
            parent, parent, 0, false, false
        ));
        for (access_acl, default_acl) in [(true, false), (false, true), (true, true)] {
            assert!(!local_account_database_directory_is_trusted(
                parent,
                parent,
                0,
                access_acl,
                default_acl,
            ));
        }
        let mut insecure_parent = parent;
        insecure_parent.mode |= 0o020;
        assert!(!local_account_database_directory_is_trusted(
            insecure_parent,
            insecure_parent,
            0,
            false,
            false,
        ));
    }

    #[test]
    fn local_account_database_root_requires_a_root_owned_nonwritable_acl_free_directory() {
        let mut root = trusted_local_account_database_node(libc::S_IFDIR);
        root.mode = libc::S_IFDIR | 0o755;
        assert!(local_account_database_root_is_trusted(
            root, 0, false, false
        ));

        let mut wrong_owner = root;
        wrong_owner.uid = 1000;
        let mut writable = root;
        writable.mode |= 0o002;
        let mut special = root;
        special.mode = libc::S_IFREG | 0o755;
        for (node, access_acl, default_acl) in [
            (wrong_owner, false, false),
            (writable, false, false),
            (special, false, false),
            (root, true, false),
            (root, false, true),
        ] {
            assert!(!local_account_database_root_is_trusted(
                node,
                0,
                access_acl,
                default_acl,
            ));
        }
    }

    #[test]
    fn local_account_database_real_scan_uses_retained_relative_files_and_clean_eof() {
        let fixture = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-local-account-db-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        let etc = fixture.join("etc");
        fs::create_dir(&fixture).unwrap();
        fs::create_dir(&etc).unwrap();
        fs::set_permissions(&fixture, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&etc, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            etc.join("passwd"),
            b"root:x:0:0:root:/root:/bin/sh\nbuild-agent:x:2001:2001::/home/build-agent:/bin/bash\n",
        )
        .unwrap();
        fs::write(etc.join("group"), b"root:x:0:\nbuild-agent:x:2001:\n").unwrap();
        for leaf in [etc.join("passwd"), etc.join("group")] {
            fs::set_permissions(leaf, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let root = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&fixture)
            .unwrap();
        let account = UnixAccountDetails {
            principal: WorkerPrincipal::new(
                PrincipalKind::UnixUid,
                "2001",
                "build-agent",
                WorkerAccountPolicy::Dedicated,
            )
            .unwrap(),
            gid: 2001,
            home: OsString::from("/home/build-agent"),
            shell: OsString::from("/bin/bash"),
        };

        assert!(local_account_records_match_at(
            &root,
            unsafe { libc::geteuid() },
            c"etc",
            &account,
            "build-agent",
        )
        .unwrap());

        fs::remove_dir_all(fixture).unwrap();
    }

    #[test]
    fn local_account_database_leaf_rejects_acl_links_special_files_and_substitution() {
        let opened = trusted_local_account_database_node(libc::S_IFREG);
        assert!(local_account_database_file_is_trusted(
            opened, opened, 0, false
        ));
        assert!(!local_account_database_file_is_trusted(
            opened, opened, 0, true
        ));

        let mut link = opened;
        link.mode = libc::S_IFLNK | 0o777;
        assert!(!local_account_database_file_is_trusted(
            opened, link, 0, false
        ));

        let mut fifo = opened;
        fifo.mode = libc::S_IFIFO | 0o644;
        assert!(!local_account_database_file_is_trusted(
            fifo, fifo, 0, false
        ));

        let mut replacement = opened;
        replacement.identity = PrivateFileIdentity::new(41, 74);
        assert!(!local_account_database_file_is_trusted(
            opened,
            replacement,
            0,
            false,
        ));
    }

    #[test]
    fn dedicated_account_observation_keeps_local_provenance_failure_distinct() {
        let spec = super::super::DedicatedAccountSpec::new("build-agent").unwrap();
        let mut record = healthy_dedicated_account_record();
        record.local_record = LinuxLocalRecordProof::Unknowable;
        assert!(matches!(
            classify_dedicated_account_record(
                &spec,
                record,
                super::super::NativeDedicatedAccountInspection::Initial,
            ),
            super::super::NativeDedicatedAccountObservation::Unknowable,
        ));
    }

    #[test]
    fn dedicated_account_observation_rejects_linux_system_range_uids() {
        let spec = super::super::DedicatedAccountSpec::new("build-agent").unwrap();
        let mut record = healthy_dedicated_account_record();
        record.principal = WorkerPrincipal::new(
            PrincipalKind::UnixUid,
            "999",
            "build-agent",
            WorkerAccountPolicy::Dedicated,
        )
        .unwrap();
        assert!(matches!(
            classify_dedicated_account_record(
                &spec,
                record,
                super::super::NativeDedicatedAccountInspection::Established,
            ),
            super::super::NativeDedicatedAccountObservation::PresentBroken,
        ));
    }

    #[test]
    fn dedicated_account_observation_rejects_each_unsafe_linux_posture() {
        let spec = super::super::DedicatedAccountSpec::new("build-agent").unwrap();
        assert!(matches!(
            classify_dedicated_account_record(
                &spec,
                healthy_dedicated_account_record(),
                super::super::NativeDedicatedAccountInspection::Initial,
            ),
            super::super::NativeDedicatedAccountObservation::PresentHealthy(_),
        ));

        let mut cases = Vec::new();
        let mut wrong_kind = healthy_dedicated_account_record();
        wrong_kind.principal = WorkerPrincipal::new(
            PrincipalKind::WindowsSid,
            "S-1-5-21-100-200-300-1001",
            "build-agent",
            WorkerAccountPolicy::Dedicated,
        )
        .unwrap();
        cases.push(wrong_kind);
        let mut non_private_primary_group = healthy_dedicated_account_record();
        non_private_primary_group.primary_group_name = Some("workers".to_owned());
        cases.push(non_private_primary_group);
        let mut wrong_home = healthy_dedicated_account_record();
        wrong_home.home = PathBuf::from("/srv/unrelated");
        cases.push(wrong_home);
        let mut wrong_shell = healthy_dedicated_account_record();
        wrong_shell.shell = PathBuf::from("/usr/sbin/nologin");
        cases.push(wrong_shell);
        let mut missing_home = healthy_dedicated_account_record();
        missing_home.home_state = DedicatedHomeState::Missing;
        cases.push(missing_home);
        let mut unsafe_home = healthy_dedicated_account_record();
        unsafe_home.home_state = DedicatedHomeState::Unsafe;
        cases.push(unsafe_home);
        let mut populated_home = healthy_dedicated_account_record();
        populated_home.home_state = DedicatedHomeState::PopulatedSafe;
        cases.push(populated_home);

        for record in cases {
            assert_dedicated_account_broken(record);
        }

        let mut unavailable_home = healthy_dedicated_account_record();
        unavailable_home.home_state = DedicatedHomeState::Unknowable;
        assert!(matches!(
            classify_dedicated_account_record(
                &spec,
                unavailable_home,
                super::super::NativeDedicatedAccountInspection::Initial,
            ),
            super::super::NativeDedicatedAccountObservation::Unknowable,
        ));

        let mut unavailable_group = healthy_dedicated_account_record();
        unavailable_group.primary_group_name = None;
        assert!(matches!(
            classify_dedicated_account_record(
                &spec,
                unavailable_group,
                super::super::NativeDedicatedAccountInspection::Initial,
            ),
            super::super::NativeDedicatedAccountObservation::Unknowable,
        ));
    }

    #[test]
    fn dedicated_account_observation_rejects_every_distinct_supplementary_group() {
        let spec = super::super::DedicatedAccountSpec::new("build-agent").unwrap();
        for (group_name, root_equivalent_gid) in [("docker", 998), ("lxd", 999)] {
            let mut record = healthy_dedicated_account_record();
            record.supplementary_groups = Some(vec![root_equivalent_gid]);
            assert!(
                matches!(
                    classify_dedicated_account_record(
                        &spec,
                        record,
                        super::super::NativeDedicatedAccountInspection::Initial,
                    ),
                    super::super::NativeDedicatedAccountObservation::PresentBroken,
                ),
                "membership in {group_name} must be rejected"
            );
        }
    }

    #[test]
    fn dedicated_account_binding_allows_safe_linux_home_contents_after_adoption() {
        let spec = super::super::DedicatedAccountSpec::new("build-agent").unwrap();
        let mut populated = healthy_dedicated_account_record();
        populated.home_state = DedicatedHomeState::PopulatedSafe;
        assert!(matches!(
            classify_dedicated_account_record(
                &spec,
                populated.clone(),
                super::super::NativeDedicatedAccountInspection::Initial,
            ),
            super::super::NativeDedicatedAccountObservation::PresentBroken,
        ));
        assert!(matches!(
            classify_dedicated_account_record(
                &spec,
                populated,
                super::super::NativeDedicatedAccountInspection::Established,
            ),
            super::super::NativeDedicatedAccountObservation::PresentHealthy(_),
        ));
    }

    #[test]
    #[ignore = "environmental: requires native Linux and STYRN_TEST_DISTINCT_UNIX_WORKER naming a non-administrator local account with an empty safe /home directory"]
    fn native_dedicated_account_observation_adopts_a_distinct_local_account() {
        let name = std::env::var("STYRN_TEST_DISTINCT_UNIX_WORKER")
            .expect("STYRN_TEST_DISTINCT_UNIX_WORKER must name a disposable local account");
        assert_ne!(name, "styrn");
        let observation = super::super::inspect_dedicated_account(
            super::super::DedicatedAccountSpec::new(&name).unwrap(),
        );
        let super::super::DedicatedAccountObservation::PresentHealthy(handle) = observation else {
            panic!("the configured Linux account did not satisfy dedicated adoption posture");
        };
        let authority = super::super::DedicatedAccountFactoryAuthority::for_test();
        handle
            .reverify_and_bind(&authority, |verified| {
                assert_eq!(verified.principal().name(), name);
                assert_eq!(
                    verified.principal().account_policy(),
                    WorkerAccountPolicy::Dedicated
                );
            })
            .unwrap();
    }

    #[test]
    fn post_mkdir_substitution_is_never_reported_as_a_created_worker_node() {
        fn substitute(parent: i32, name: &std::ffi::CStr) {
            let displaced = c".styrn-test-displaced";
            assert_eq!(
                unsafe { libc::renameat(parent, name.as_ptr(), parent, displaced.as_ptr()) },
                0,
                "{}",
                io::Error::last_os_error()
            );
            assert_eq!(
                unsafe { libc::mkdirat(parent, name.as_ptr(), 0o700) },
                0,
                "{}",
                io::Error::last_os_error()
            );
        }

        let principal = resolve_current_worker_principal().unwrap();
        for scope in [
            crate::platform::InstallationScope::User,
            crate::platform::InstallationScope::System,
        ] {
            let parent = fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "styrn-worker-post-mkdir-swap-{scope:?}-{}-{}",
                    std::process::id(),
                    uuid::Uuid::now_v7()
                ));
            fs::create_dir(&parent).unwrap();
            let root = parent.join("root");
            let layout =
                crate::platform::resolve_worker_directory_layout(scope, &principal, Some(&root))
                    .unwrap();
            set_post_worker_mkdir_hook(substitute);

            let error = create_worker_directory_layout(&layout).unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(!root.exists());
            fs::remove_dir_all(parent).unwrap();
        }
    }

    #[test]
    fn creator_only_unpublished_parent_requires_distinct_worker_and_live_identity() {
        let outer = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-creator-only-capability-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        fs::create_dir(&outer).unwrap();
        let staging_path = outer.join("private-root");
        let canonical_path = outer.join("root");
        fs::create_dir(&staging_path).unwrap();
        fs::set_permissions(&staging_path, fs::Permissions::from_mode(0o700)).unwrap();
        let staging_parent = open_existing_worker_path(&outer).unwrap();
        let directory = open_existing_worker_path(&staging_path).unwrap();
        let staged = StagedWorkerDirectory {
            name: CString::new("private-root").unwrap(),
            identity: worker_directory_identity(&directory).unwrap(),
            directory,
            created: false,
        };
        let creator_uid = unsafe { libc::geteuid() };
        let distinct_worker_uid = creator_uid.checked_add(1).unwrap();

        {
            let capability = verify_unpublished_worker_recovery_authority(
                &staged,
                &staging_parent,
                &staging_parent,
                b"root",
                distinct_worker_uid,
            )
            .unwrap()
            .expect("a retained creator-only parent should mint authority for a distinct worker");
            capability.reverify_parent(&staged.directory).unwrap();
            assert!(verify_unpublished_worker_recovery_authority(
                &staged,
                &staging_parent,
                &staging_parent,
                b"root",
                creator_uid,
            )
            .is_err());
            fs::set_permissions(&staging_path, fs::Permissions::from_mode(0o750)).unwrap();
            assert!(capability.reverify_parent(&staged.directory).is_err());
            fs::set_permissions(&staging_path, fs::Permissions::from_mode(0o700)).unwrap();
            capability.reverify_parent(&staged.directory).unwrap();

            fs::create_dir(&canonical_path).unwrap();
            capability.reverify_parent(&staged.directory).unwrap();
            fs::remove_dir(&canonical_path).unwrap();

            fs::rename(&staging_path, &canonical_path).unwrap();
            fs::create_dir(&staging_path).unwrap();
            fs::set_permissions(&staging_path, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(capability.reverify_parent(&staged.directory).is_err());
        }
        drop(staged);
        drop(staging_parent);
        fs::remove_dir(staging_path).unwrap();
        fs::remove_dir(canonical_path).unwrap();
        fs::remove_dir(outer).unwrap();
    }

    #[test]
    #[ignore = "environmental: requires root on native Linux and STYRN_TEST_DISTINCT_UNIX_WORKER naming a disposable distinct local account"]
    fn creator_only_unpublished_parent_recovers_distinct_worker_children() {
        let worker_name = std::env::var("STYRN_TEST_DISTINCT_UNIX_WORKER")
            .expect("STYRN_TEST_DISTINCT_UNIX_WORKER must name a disposable local account");
        let principal =
            resolve_named_worker_principal(&worker_name, WorkerAccountPolicy::Dedicated).unwrap();
        assert_ne!(principal.unix_uid().unwrap(), unsafe { libc::geteuid() });
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-distinct-recovery-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("root");
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::System,
            &principal,
            Some(&root),
        )
        .unwrap();

        set_worker_mkdir_interrupt_after(Some(1));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            create_worker_directory_layout(&layout)
        }));
        set_worker_mkdir_interrupt_after(None);
        assert!(interrupted.is_err());
        assert!(!root.exists());

        let creation = create_worker_directory_layout(&layout).unwrap();
        let dispositions = creation
            .bind_after_reverify(|binding| {
                Ok::<_, ()>(
                    binding
                        .observations()
                        .iter()
                        .map(|node| node.disposition())
                        .collect::<Vec<_>>(),
                )
            })
            .unwrap();
        assert_eq!(dispositions.len(), 6);
        assert!(dispositions.iter().all(|disposition| {
            *disposition == crate::platform::WorkerDirectoryNodeDisposition::Created
        }));

        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn same_uid_interrupted_worker_staging_is_retained_as_a_conflict() {
        let principal = resolve_current_worker_principal().unwrap();
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-staging-resume-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("root");
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::System,
            &principal,
            Some(&root),
        )
        .unwrap();

        set_worker_mkdir_interrupt_after(Some(1));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            create_worker_directory_layout(&layout)
        }));
        set_worker_mkdir_interrupt_after(None);
        assert!(interrupted.is_err());
        assert!(!root.exists());
        let parent_directory = open_existing_worker_path(&parent).unwrap();
        let retained_before = worker_parent_entry_snapshot(&parent_directory).unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!root.exists());
        assert_eq!(
            worker_parent_entry_snapshot(&parent_directory).unwrap(),
            retained_before
        );
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn same_uid_interruption_after_provenance_retains_conflict_evidence() {
        let principal = resolve_current_worker_principal().unwrap();
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-provenance-recovery-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("root");
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::System,
            &principal,
            Some(&root),
        )
        .unwrap();

        set_worker_publication_interrupt(Some(WorkerPublicationInterruption::AfterProvenance));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            create_worker_directory_layout(&layout)
        }));
        set_worker_publication_interrupt(None);
        assert!(interrupted.is_err());
        assert!(!root.exists());
        let parent_directory = open_existing_worker_path(&parent).unwrap();
        let retained_before = worker_parent_entry_snapshot(&parent_directory).unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!root.exists());
        assert_eq!(
            worker_parent_entry_snapshot(&parent_directory).unwrap(),
            retained_before
        );
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn deleted_worker_child_with_replayed_identity_remains_conflict_evidence() {
        let principal = resolve_current_worker_principal().unwrap();
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-provenance-identity-reuse-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("root");
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::System,
            &principal,
            Some(&root),
        )
        .unwrap();

        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in super::super::WorkerDirectoryLayout::child_names()
            .into_iter()
            .filter(|name| *name != "repos")
        {
            let child = root.join(name);
            fs::create_dir(&child).unwrap();
            fs::set_permissions(child, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let unbound_creation = create_worker_directory_layout(&layout).unwrap();
        drop(unbound_creation);
        let original = open_existing_worker_path(&root.join("repos")).unwrap();
        let replayed_identity = worker_directory_identity(&original).unwrap();
        drop(original);
        fs::remove_dir(root.join("repos")).unwrap();
        fs::create_dir(root.join("repos")).unwrap();
        fs::set_permissions(root.join("repos"), fs::Permissions::from_mode(0o700)).unwrap();
        let replacement = open_existing_worker_path(&root.join("repos")).unwrap();
        let replacement_identity = worker_directory_identity(&replacement).unwrap();
        let parent_directory = open_existing_worker_path(&parent).unwrap();
        let retained_before = worker_parent_entry_snapshot(&parent_directory).unwrap();
        set_worker_recovery_identity_override(Some((b"repos".to_vec(), replayed_identity)));

        let result = create_worker_directory_layout(&layout);
        set_worker_recovery_identity_override(None);
        let error = result.unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            worker_directory_identity(&open_existing_worker_path(&root.join("repos")).unwrap())
                .unwrap(),
            replacement_identity
        );
        assert_eq!(
            worker_parent_entry_snapshot(&parent_directory).unwrap(),
            retained_before
        );
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn worker_substituted_compliant_child_is_not_relabelled_created_during_recovery() {
        let principal = resolve_current_worker_principal().unwrap();
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-provenance-substitution-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("root");
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::System,
            &principal,
            Some(&root),
        )
        .unwrap();

        set_worker_publication_interrupt(Some(WorkerPublicationInterruption::AfterRootOwnership));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            create_worker_directory_layout(&layout)
        }));
        set_worker_publication_interrupt(None);
        assert!(interrupted.is_err());
        assert!(root.is_dir());
        let displaced = root.join("repos-created-by-styrn");
        fs::rename(root.join("repos"), &displaced).unwrap();
        fs::create_dir(root.join("repos")).unwrap();
        fs::set_permissions(root.join("repos"), fs::Permissions::from_mode(0o700)).unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(root.join("repos").is_dir());
        assert!(displaced.is_dir());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn ambiguous_interrupted_worker_staging_is_rejected_without_cleanup_or_adoption() {
        let principal = resolve_current_worker_principal().unwrap();
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-staging-ambiguous-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("root");
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::System,
            &principal,
            Some(&root),
        )
        .unwrap();

        set_worker_mkdir_interrupt_after(Some(0));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            create_worker_directory_layout(&layout)
        }));
        set_worker_mkdir_interrupt_after(None);
        assert!(interrupted.is_err());
        let staged = fs::read_dir(&parent)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let unrelated = staged.join("operator-entry");
        fs::create_dir(&unrelated).unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!root.exists());
        assert!(unrelated.is_dir());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn canonical_worker_acl_policy_rejects_access_and_default_acl_presence() {
        assert!(validate_worker_acl_presence(false, false).is_ok());
        assert!(validate_worker_acl_presence(true, false).is_err());
        assert!(validate_worker_acl_presence(false, true).is_err());
        assert!(validate_worker_acl_presence(true, true).is_err());
    }

    #[test]
    #[ignore = "environmental: requires native Linux filesystem POSIX access/default ACL support"]
    fn native_existing_access_or_default_acl_is_rejected_without_rewrite() {
        for attribute in [c"system.posix_acl_access", c"system.posix_acl_default"] {
            let principal = resolve_current_worker_principal().unwrap();
            let parent = fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "styrn-worker-existing-posix-acl-{}-{}",
                    std::process::id(),
                    uuid::Uuid::now_v7()
                ));
            let root = parent.join("root");
            fs::create_dir_all(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            set_test_posix_acl(&root, attribute);
            let layout = crate::platform::resolve_worker_directory_layout(
                crate::platform::InstallationScope::System,
                &principal,
                Some(&root),
            )
            .unwrap();

            let error = create_worker_directory_layout(&layout).unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(posix_acl_present_path(&root, attribute).unwrap());
            assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
            remove_test_posix_acl(&root, attribute);
            fs::remove_dir_all(parent).unwrap();
        }
    }

    #[test]
    #[ignore = "environmental: requires native Linux filesystem POSIX default ACL inheritance"]
    fn native_new_worker_nodes_clear_inherited_access_and_default_acls() {
        let principal = resolve_current_worker_principal().unwrap();
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-inherited-posix-acl-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        let profile = parent.join("profile");
        fs::create_dir_all(&profile).unwrap();
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o700)).unwrap();
        set_test_posix_acl(&profile, c"system.posix_acl_default");
        let probe = profile.join("inheritance-probe");
        fs::create_dir(&probe).unwrap();
        assert!(posix_acl_present_path(&probe, c"system.posix_acl_access").unwrap());
        assert!(posix_acl_present_path(&probe, c"system.posix_acl_default").unwrap());
        remove_test_posix_acl(&probe, c"system.posix_acl_access");
        remove_test_posix_acl(&probe, c"system.posix_acl_default");
        fs::remove_dir(&probe).unwrap();
        let root = profile.join("new/data/styrn");
        let layout = crate::platform::WorkerDirectoryLayout::new(
            crate::platform::InstallationScope::User,
            root.clone(),
            crate::platform::WorkerRootCreationPolicy::CreateMissingFrom(profile.clone()),
            principal,
        );

        create_worker_directory_layout(&layout).unwrap();

        for path in [
            profile.join("new"),
            profile.join("new/data"),
            root.clone(),
            root.join("repos"),
            root.join("jobs"),
            root.join("cache"),
            root.join("artifacts"),
            root.join("logs"),
        ] {
            assert!(!posix_acl_present_path(&path, c"system.posix_acl_access").unwrap());
            assert!(!posix_acl_present_path(&path, c"system.posix_acl_default").unwrap());
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        remove_test_posix_acl(&profile, c"system.posix_acl_default");
        fs::remove_dir_all(parent).unwrap();
    }

    fn set_test_posix_acl(path: &Path, attribute: &std::ffi::CStr) {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let mut value = 2_u32.to_le_bytes().to_vec();
        for (tag, permissions, id) in [
            (0x01_u16, 0x07_u16, u32::MAX),
            (
                0x02_u16,
                0x07_u16,
                unsafe { libc::geteuid() }.wrapping_add(1),
            ),
            (0x04_u16, 0x00_u16, u32::MAX),
            (0x10_u16, 0x07_u16, u32::MAX),
            (0x20_u16, 0x00_u16, u32::MAX),
        ] {
            value.extend_from_slice(&tag.to_le_bytes());
            value.extend_from_slice(&permissions.to_le_bytes());
            value.extend_from_slice(&id.to_le_bytes());
        }
        assert_eq!(
            unsafe {
                libc::setxattr(
                    path.as_ptr(),
                    attribute.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            },
            0,
            "{}",
            io::Error::last_os_error()
        );
    }

    fn posix_acl_present_path(path: &Path, attribute: &std::ffi::CStr) -> io::Result<bool> {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let size =
            unsafe { libc::getxattr(path.as_ptr(), attribute.as_ptr(), std::ptr::null_mut(), 0) };
        if size >= 0 {
            return Ok(size > 0);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ENODATA | libc::ENOTSUP) => Ok(false),
            _ => Err(error),
        }
    }

    fn remove_test_posix_acl(path: &Path, attribute: &std::ffi::CStr) {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let result = unsafe { libc::removexattr(path.as_ptr(), attribute.as_ptr()) };
        assert!(result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA));
    }

    #[test]
    fn retained_worker_root_identity_detects_path_replacement() {
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-root-swap-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        let root = parent.join("root");
        fs::create_dir_all(&root).unwrap();
        let retained = open_existing_worker_path(&root).unwrap();
        let identity = worker_directory_identity(&retained).unwrap();
        let displaced = parent.join("displaced");
        fs::rename(&root, &displaced).unwrap();
        fs::create_dir(&root).unwrap();

        let error = verify_worker_path_identity(&root, identity).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn deterministic_policy_rejects_wrong_owner_and_worker_write_paths() {
        let valid = UnixManifestInspection {
            expected_uid: 0,
            file_uid: 0,
            file_mode: 0o644,
            directory_uid: 0,
            directory_mode: 0o755,
        };
        assert!(validate_manifest_inspection(&UnixManifestInspection {
            file_uid: 1,
            ..valid
        })
        .is_err());
        assert!(validate_manifest_inspection(&UnixManifestInspection {
            file_mode: 0o664,
            ..valid
        })
        .is_err());
        assert!(validate_manifest_inspection(&UnixManifestInspection {
            directory_mode: 0o775,
            ..valid
        })
        .is_err());
        for directory_mode in [0o700, 0o750] {
            assert!(validate_manifest_inspection(&UnixManifestInspection {
                directory_mode,
                ..valid
            })
            .is_err());
        }
        assert!(validate_manifest_inspection(&valid).is_ok());
    }

    #[test]
    fn worker_owned_read_only_ancestor_is_still_rejected() {
        assert!(validate_ancestor_access(41, 0o555, Some(41), true).is_err());
    }

    #[test]
    fn user_ancestor_policy_accepts_sticky_protection_and_rejects_takeover_authority() {
        let mut reached_system_owner = false;
        assert!(
            validate_user_ancestor_access(0, 0o1777, 41, 41, &mut reached_system_owner,).is_ok()
        );
        assert!(reached_system_owner);

        let mut user_owned_chain = false;
        assert!(validate_user_ancestor_access(41, 0o0777, 41, 41, &mut user_owned_chain,).is_err());
        let mut unrelated_owner_chain = false;
        assert!(
            validate_user_ancestor_access(42, 0o0755, 41, 41, &mut unrelated_owner_chain,).is_err()
        );
        let mut invalid_reverse_transition = true;
        assert!(
            validate_user_ancestor_access(41, 0o0755, 0, 41, &mut invalid_reverse_transition,)
                .is_err()
        );
    }
}
