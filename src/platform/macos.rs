use super::ManifestOwner;
use std::fs;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

#[allow(dead_code)]
pub(crate) fn platform_name() -> &'static str {
    "macos"
}

pub(super) fn harden_manifest_directory(
    path: &Path,
    owner: ManifestOwner,
    _worker: &str,
) -> io::Result<()> {
    require_real_directory(path)?;
    apply_owner(path, owner)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    verify_directory(path, owner)
}

pub(super) fn harden_manifest_file(
    path: &Path,
    owner: ManifestOwner,
    _worker: &str,
) -> io::Result<()> {
    require_regular_file(path)?;
    apply_owner(path, owner)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    verify_file(path, owner, 0o644, "manifest")
}

pub(super) fn harden_manifest_lock(path: &Path, owner: ManifestOwner) -> io::Result<()> {
    require_regular_file(path)?;
    apply_owner(path, owner)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    verify_file(path, owner, 0o600, "manifest lock")
}

pub(super) fn open_manifest_lock(path: &Path, owner: ManifestOwner) -> io::Result<fs::File> {
    let created = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path);
    let file = match created {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            harden_manifest_lock(path, owner)?;
            fs::OpenOptions::new().read(true).write(true).open(path)?
        }
        Err(error) => return Err(error),
    };
    harden_manifest_lock(path, owner)?;
    Ok(file)
}

pub(super) fn create_manifest_temporary(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

pub(super) fn verify_manifest_security(
    path: &Path,
    owner: ManifestOwner,
    _worker: &str,
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
        #[cfg(test)]
        ManifestOwner::CurrentProcess => file.uid(),
    };
    validate_manifest_inspection(&UnixManifestInspection {
        expected_uid,
        file_uid: file.uid(),
        file_mode: file.mode() & 0o777,
        directory_uid: directory.uid(),
        directory_mode: directory.mode() & 0o777,
    })
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
    if inspection.directory_mode & 0o022 != 0 {
        return Err(permission_denied(
            "manifest directory grants group/other replacement access",
        ));
    }
    Ok(())
}

fn apply_owner(path: &Path, owner: ManifestOwner) -> io::Result<()> {
    match owner {
        ManifestOwner::System => std::os::unix::fs::chown(path, Some(0), Some(0)),
        #[cfg(test)]
        ManifestOwner::CurrentProcess => Ok(()),
    }
}

fn verify_directory(path: &Path, owner: ManifestOwner) -> io::Result<()> {
    require_real_directory(path)?;
    let metadata = fs::metadata(path)?;
    verify_owner(&metadata, owner, "manifest directory")?;
    if metadata.mode() & 0o022 != 0 {
        return Err(permission_denied(
            "manifest directory grants group/other replacement access",
        ));
    }
    Ok(())
}

fn verify_file(path: &Path, owner: ManifestOwner, mode: u32, label: &str) -> io::Result<()> {
    require_regular_file(path)?;
    let metadata = fs::metadata(path)?;
    verify_owner(&metadata, owner, label)?;
    if metadata.mode() & 0o777 != mode {
        return Err(permission_denied(&format!(
            "{label} mode must be {mode:04o}, found {:04o}",
            metadata.mode() & 0o777
        )));
    }
    Ok(())
}

fn verify_owner(metadata: &fs::Metadata, owner: ManifestOwner, label: &str) -> io::Result<()> {
    let expected = match owner {
        ManifestOwner::System => 0,
        #[cfg(test)]
        ManifestOwner::CurrentProcess => metadata.uid(),
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
        assert!(validate_manifest_inspection(&valid).is_ok());
    }
}
