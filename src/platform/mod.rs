#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;

use std::path::Path;

#[derive(Clone, Copy, Debug)]
pub(crate) enum ManifestOwner {
    System,
    #[cfg(test)]
    CurrentProcess,
    #[cfg(test)]
    CurrentProcessWorker,
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

pub(crate) fn create_manifest_temporary(path: &Path) -> std::io::Result<std::fs::File> {
    platform_impl::create_manifest_temporary(path)
}

pub(crate) fn verify_manifest_security(
    path: &Path,
    owner: ManifestOwner,
    worker: &str,
    trusted_root: &Path,
) -> std::io::Result<()> {
    platform_impl::verify_manifest_security(path, owner, worker, trusted_root)
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
    staging: &Path,
    destination: &Path,
) -> std::io::Result<()> {
    platform_impl::publish_manifest_directory(staging, destination)
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

#[cfg(target_os = "linux")]
use linux as platform_impl;

#[cfg(target_os = "macos")]
use macos as platform_impl;

#[cfg(target_os = "windows")]
use windows as platform_impl;
