#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;

use std::path::Path;

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
