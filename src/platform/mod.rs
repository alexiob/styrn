#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;

use std::path::Path;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug)]
pub(crate) enum ManifestOwner {
    System,
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

impl PrivateManifestStagingDirectory {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

pub(crate) fn create_private_manifest_staging_directory(
    path: &Path,
    owner: ManifestOwner,
) -> std::io::Result<PrivateManifestStagingDirectory> {
    platform_impl::create_private_manifest_staging_directory(path, owner)?;
    Ok(PrivateManifestStagingDirectory {
        path: path.to_path_buf(),
    })
}

pub(crate) fn harden_manifest_directory(
    path: &Path,
    owner: ManifestOwner,
    worker: &str,
) -> std::io::Result<()> {
    platform_impl::harden_manifest_directory(path, owner, worker)
}

pub(crate) fn harden_manifest_file(
    path: &Path,
    owner: ManifestOwner,
    worker: &str,
) -> std::io::Result<()> {
    platform_impl::harden_manifest_file(path, owner, worker)
}

pub(crate) fn open_manifest_lock(
    path: &Path,
    owner: ManifestOwner,
) -> std::io::Result<std::fs::File> {
    platform_impl::open_manifest_lock(path, owner)
}

#[allow(dead_code)] // Source-including manifest tests do not include receipt recovery.
pub(crate) fn verify_private_file_security(
    path: &Path,
    owner: ManifestOwner,
) -> std::io::Result<()> {
    platform_impl::verify_private_file_security(path, owner)
}

pub(crate) fn create_private_file(
    path: &Path,
    owner: ManifestOwner,
) -> std::io::Result<std::fs::File> {
    platform_impl::create_private_file(path, owner)
}

pub(crate) fn verify_manifest_security(
    path: &Path,
    owner: ManifestOwner,
    worker: &str,
    trusted_root: &Path,
) -> std::io::Result<()> {
    platform_impl::verify_manifest_security(path, owner, worker, trusted_root)
}

#[allow(dead_code)] // Source-including manifest tests do not include receipt reads.
pub(crate) fn open_verified_manifest_file_for_read(
    path: &Path,
    owner: ManifestOwner,
    worker: &str,
    trusted_root: &Path,
) -> std::io::Result<std::fs::File> {
    platform_impl::open_verified_manifest_file_for_read(path, owner, worker, trusted_root)
}

pub(crate) fn verify_manifest_ancestors(
    directory: &Path,
    owner: ManifestOwner,
    worker: &str,
    trusted_root: &Path,
) -> std::io::Result<()> {
    platform_impl::verify_manifest_ancestors(directory, owner, worker, trusted_root)
}

pub(crate) fn verify_manifest_parent_chain(
    parent: &Path,
    owner: ManifestOwner,
    worker: &str,
) -> std::io::Result<()> {
    platform_impl::verify_manifest_parent_chain(parent, owner, worker)
}

pub(crate) fn verify_manifest_directory_security(
    directory: &Path,
    owner: ManifestOwner,
    worker: &str,
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
