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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PrincipalKind {
    UnixUid,
    WindowsSid,
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
}

impl WorkerPrincipal {
    pub(crate) fn new(
        principal_kind: PrincipalKind,
        principal_id: impl Into<String>,
        name: impl Into<String>,
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
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.principal_kind, wire.principal_id, wire.name)
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
        assert!(WorkerPrincipal::new(PrincipalKind::UnixUid, "501", "123-build$").is_ok());
        for id in ["", "0", "0501", "4294967296", "-1"] {
            assert!(
                WorkerPrincipal::new(PrincipalKind::UnixUid, id, "worker").is_err(),
                "{id}"
            );
        }
        assert!(WorkerPrincipal::new(
            PrincipalKind::WindowsSid,
            "S-1-5-21-1-2-3-1001",
            "build.agent$",
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
                WorkerPrincipal::new(PrincipalKind::WindowsSid, id, "worker").is_err(),
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
            assert!(WorkerPrincipal::new(PrincipalKind::UnixUid, "501", name).is_err());
        }
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
        let first = WorkerPrincipal::new(PrincipalKind::UnixUid, "501", "same-name").unwrap();
        let replacement = WorkerPrincipal::new(PrincipalKind::UnixUid, "502", "same-name").unwrap();
        assert_eq!(first.unix_uid().unwrap(), 501);
        assert_eq!(replacement.unix_uid().unwrap(), 502);
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

/// A staging pathname created with the platform's private-at-creation policy.
///
/// The containing parent is verified against worker takeover before this value
/// is minted, so keeping its field private prevents generic code from
/// publishing a separately created or worker-authorized directory.
pub(crate) struct PrivateManifestStagingDirectory {
    path: PathBuf,
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
pub(crate) fn resolve_named_worker_principal(name: &str) -> std::io::Result<WorkerPrincipal> {
    platform_impl::resolve_named_worker_principal(name)
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
