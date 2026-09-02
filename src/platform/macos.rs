use super::{ManifestOwner, PrivateFileIdentity};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

type Acl = *mut std::ffi::c_void;
type AclEntry = *mut std::ffi::c_void;
#[cfg(test)]
type AclPermset = *mut std::ffi::c_void;

const ACL_TYPE_EXTENDED: i32 = 0x100;
const ACL_FIRST_ENTRY: i32 = 0;
const ACL_NEXT_ENTRY: i32 = -1;
const ACL_EXTENDED_ALLOW: i32 = 1;
const ACL_EXTENDED_DENY: i32 = 2;
#[cfg(test)]
const ACL_WRITE_DATA: i32 = 1 << 2;
#[cfg(test)]
const ACL_DELETE: i32 = 1 << 4;
#[cfg(test)]
const ACL_DELETE_CHILD: i32 = 1 << 6;

unsafe extern "C" {
    fn renamex_np(old: *const i8, new: *const i8, flags: u32) -> i32;
    fn acl_init(count: i32) -> Acl;
    fn acl_free(object: *mut std::ffi::c_void) -> i32;
    fn acl_get_file(path: *const i8, kind: i32) -> Acl;
    #[allow(dead_code)]
    fn acl_get_fd_np(fd: i32, kind: i32) -> Acl;
    fn acl_set_file(path: *const i8, kind: i32, acl: Acl) -> i32;
    fn acl_get_entry(acl: Acl, entry_id: i32, entry: *mut AclEntry) -> i32;
    fn acl_get_tag_type(entry: AclEntry, tag: *mut i32) -> i32;
    #[cfg(test)]
    fn acl_create_entry(acl: *mut Acl, entry: *mut AclEntry) -> i32;
    #[cfg(test)]
    fn acl_set_tag_type(entry: AclEntry, tag: i32) -> i32;
    #[cfg(test)]
    fn acl_set_qualifier(entry: AclEntry, qualifier: *const std::ffi::c_void) -> i32;
    #[cfg(test)]
    fn acl_get_permset(entry: AclEntry, permset: *mut AclPermset) -> i32;
    #[cfg(test)]
    fn acl_add_perm(permset: AclPermset, permission: i32) -> i32;
    #[cfg(test)]
    fn mbr_uid_to_uuid(uid: u32, uuid: *mut u8) -> i32;
}

#[allow(dead_code)]
pub(crate) fn platform_name() -> &'static str {
    "macos"
}

pub(super) fn create_private_manifest_staging_directory(
    path: &Path,
    _owner: ManifestOwner,
) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

pub(super) fn harden_manifest_directory(
    path: &Path,
    owner: ManifestOwner,
    _worker: &str,
) -> io::Result<()> {
    require_real_directory(path)?;
    clear_extended_acl(path)?;
    apply_owner(path, owner)?;
    let mode = if matches!(owner, ManifestOwner::User) {
        0o700
    } else {
        0o755
    };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    verify_directory(path, owner)
}

pub(super) fn harden_manifest_file(
    path: &Path,
    owner: ManifestOwner,
    _worker: &str,
) -> io::Result<()> {
    require_regular_file(path)?;
    clear_extended_acl(path)?;
    apply_owner(path, owner)?;
    let mode = if matches!(owner, ManifestOwner::User) {
        0o600
    } else {
        0o644
    };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    verify_file(path, owner, mode, "manifest")
}

pub(super) fn open_manifest_lock(path: &Path, owner: ManifestOwner) -> io::Result<fs::File> {
    let created = create_private_file(path, owner);
    let file = match created {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            verify_private_file_security(path, owner)?;
            fs::OpenOptions::new().read(true).write(true).open(path)?
        }
        Err(error) => return Err(error),
    };
    verify_private_file_security(path, owner)?;
    Ok(file)
}

pub(super) fn verify_private_file_security(path: &Path, owner: ManifestOwner) -> io::Result<()> {
    verify_file(path, owner, 0o600, "private store file")
}

pub(super) fn create_private_file(path: &Path, _owner: ManifestOwner) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
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

pub(super) fn open_verified_private_file_for_read(
    path: &Path,
    owner: ManifestOwner,
    expected_identity: PrivateFileIdentity,
) -> io::Result<fs::File> {
    use std::os::fd::AsRawFd;

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
        ManifestOwner::User => unsafe { libc::geteuid() },
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => metadata.uid(),
    };
    if metadata.uid() != expected_uid || metadata.mode() & 0o777 != 0o600 {
        return Err(permission_denied(
            "private store file ownership or mode is insecure",
        ));
    }
    verify_no_extended_acl_fd(file.as_raw_fd())?;
    Ok(file)
}

pub(super) fn verify_manifest_security(
    path: &Path,
    owner: ManifestOwner,
    worker: &str,
    trusted_root: &Path,
) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("manifest path has no parent directory"))?;
    require_real_directory(parent)?;
    require_regular_file(path)?;
    verify_no_extended_acl(parent)?;
    verify_no_extended_acl(path)?;
    let file = fs::metadata(path)?;
    let directory = fs::metadata(parent)?;
    let expected_uid = match owner {
        ManifestOwner::System => 0,
        ManifestOwner::User => unsafe { libc::geteuid() },
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
    worker: &str,
    trusted_root: &Path,
) -> io::Result<fs::File> {
    use std::os::fd::AsRawFd;

    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("manifest path has no parent directory"))?;
    require_real_directory(parent)?;
    verify_no_extended_acl(parent)?;
    verify_manifest_ancestors(parent, owner, worker, trusted_root)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let file_metadata = file.metadata()?;
    if !file_metadata.is_file() {
        return Err(permission_denied("manifest target is not a regular file"));
    }
    verify_no_extended_acl_fd(file.as_raw_fd())?;
    let directory = fs::metadata(parent)?;
    let expected_uid = match owner {
        ManifestOwner::System => 0,
        ManifestOwner::User => unsafe { libc::geteuid() },
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
    verify_no_extended_acl(parent)?;
    verify_manifest_ancestors(parent, owner, worker, trusted_root)?;
    Ok(file)
}

pub(super) fn verify_manifest_file_target(path: &Path) -> io::Result<()> {
    require_regular_file(path)
}

pub(super) fn verify_manifest_directory_security(
    directory: &Path,
    owner: ManifestOwner,
    _worker: &str,
) -> io::Result<()> {
    verify_directory(directory, owner)
}

pub(super) fn publish_manifest_directory(staging: &Path, destination: &Path) -> io::Result<()> {
    const RENAME_EXCL: u32 = 0x0000_0004;
    require_real_directory(staging)?;
    let staging = std::ffi::CString::new(staging.as_os_str().as_bytes())
        .map_err(|_| invalid_data("manifest staging path contains a NUL byte"))?;
    let destination = std::ffi::CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| invalid_data("manifest destination path contains a NUL byte"))?;
    if unsafe { renamex_np(staging.as_ptr(), destination.as_ptr(), RENAME_EXCL) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn verify_manifest_parent_chain(
    parent: &Path,
    owner: ManifestOwner,
    worker: &str,
) -> io::Result<()> {
    if matches!(owner, ManifestOwner::User) {
        return verify_user_trusted_root_chain(parent);
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
    worker: &str,
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
        return verify_user_manifest_ancestors(directory, trusted_root);
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
        verify_no_extended_acl(ancestor)?;
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

fn verify_user_manifest_ancestors(directory: &Path, trusted_root: &Path) -> io::Result<()> {
    require_real_directory(directory)?;
    if directory != trusted_root {
        let current_uid = unsafe { libc::geteuid() };
        let mut current = directory.parent();
        while let Some(ancestor) = current {
            if ancestor == trusted_root {
                break;
            }
            require_real_directory(ancestor)?;
            verify_no_extended_acl(ancestor)?;
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
    verify_user_trusted_root_chain(trusted_root)
}

fn verify_user_trusted_root_chain(path: &Path) -> io::Result<()> {
    verify_user_trusted_root(path)?;
    let metadata = fs::metadata(path)?;
    let current_uid = unsafe { libc::geteuid() };
    let mut child_uid = metadata.uid();
    let mut reached_system_owner = false;
    let mut current = path.parent();
    while let Some(ancestor) = current {
        require_real_directory(ancestor)?;
        verify_trusted_root_has_no_extended_allow_acl(ancestor)?;
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

fn verify_user_trusted_root(path: &Path) -> io::Result<()> {
    require_real_directory(path)?;
    verify_trusted_root_has_no_extended_allow_acl(path)?;
    let metadata = fs::metadata(path)?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
        return Err(permission_denied(
            "user state root owner or write permissions are insecure",
        ));
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

fn verify_trusted_root_has_no_extended_allow_acl(path: &Path) -> io::Result<()> {
    let acl = unsafe { acl_get_file(c_path(path)?.as_ptr(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(error)
        };
    }
    let acl = OwnedAcl(acl);
    let mut entry_id = ACL_FIRST_ENTRY;
    loop {
        let mut entry = std::ptr::null_mut();
        let status = unsafe { acl_get_entry(acl.0, entry_id, &mut entry) };
        if (status == 0 || status == 1) && !entry.is_null() {
            let mut tag = 0;
            if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 {
                return Err(io::Error::last_os_error());
            }
            if tag == ACL_EXTENDED_ALLOW {
                return Err(permission_denied(
                    "user state root contains an extended allow ACL",
                ));
            }
            if tag != ACL_EXTENDED_DENY {
                return Err(permission_denied(
                    "user state root contains an unrecognized extended ACL",
                ));
            }
            entry_id = ACL_NEXT_ENTRY;
            continue;
        }
        if (status == 0 || status == -1) && entry.is_null() {
            let error = io::Error::last_os_error();
            if status == 0 || error.raw_os_error() == Some(libc::EINVAL) {
                return Ok(());
            }
            return Err(error);
        }
        return Err(io::Error::last_os_error());
    }
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
        verify_no_extended_acl(ancestor)?;
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

fn worker_uid(owner: ManifestOwner, worker: &str) -> io::Result<Option<u32>> {
    match owner {
        ManifestOwner::System => Ok(Some(lookup_worker_uid(worker)?)),
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

fn verify_directory(path: &Path, owner: ManifestOwner) -> io::Result<()> {
    require_real_directory(path)?;
    verify_no_extended_acl(path)?;
    let metadata = fs::metadata(path)?;
    verify_owner(&metadata, owner, "manifest directory")?;
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

fn verify_file(path: &Path, owner: ManifestOwner, mode: u32, label: &str) -> io::Result<()> {
    require_regular_file(path)?;
    verify_no_extended_acl(path)?;
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

fn clear_extended_acl(path: &Path) -> io::Result<()> {
    let acl = unsafe { acl_init(0) };
    if acl.is_null() {
        return Err(io::Error::last_os_error());
    }
    let acl = OwnedAcl(acl);
    let path = c_path(path)?;
    if unsafe { acl_set_file(path.as_ptr(), ACL_TYPE_EXTENDED, acl.0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    verify_no_extended_acl_c_path(&path)
}

fn verify_no_extended_acl(path: &Path) -> io::Result<()> {
    verify_no_extended_acl_c_path(&c_path(path)?)
}

#[allow(dead_code)] // Source-including manifest tests do not include receipt reads.
fn verify_no_extended_acl_fd(fd: i32) -> io::Result<()> {
    verify_no_extended_acl_value(unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) })
}

fn verify_no_extended_acl_c_path(path: &std::ffi::CString) -> io::Result<()> {
    verify_no_extended_acl_value(unsafe { acl_get_file(path.as_ptr(), ACL_TYPE_EXTENDED) })
}

fn verify_no_extended_acl_value(acl: Acl) -> io::Result<()> {
    if acl.is_null() {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(error)
        };
    }
    let acl = OwnedAcl(acl);
    let mut entry = std::ptr::null_mut();
    match unsafe { acl_get_entry(acl.0, ACL_FIRST_ENTRY, &mut entry) } {
        0 => Err(permission_denied(
            "manifest security target has an extended ACL",
        )),
        _ => Err(io::Error::last_os_error()),
    }
}

fn c_path(path: &Path) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| invalid_data("manifest path contains a NUL byte"))
}

struct OwnedAcl(Acl);

impl Drop for OwnedAcl {
    fn drop(&mut self) {
        unsafe {
            acl_free(self.0);
        }
    }
}

fn verify_owner(metadata: &fs::Metadata, owner: ManifestOwner, label: &str) -> io::Result<()> {
    let expected = match owner {
        ManifestOwner::System => 0,
        ManifestOwner::User => unsafe { libc::geteuid() },
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

    #[test]
    fn extended_mutation_acl_survives_chmod_and_must_be_rejected() {
        let directory = std::env::temp_dir().join(format!(
            "styrn-macos-acl-red-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("machine.toml");
        fs::write(&path, "schema_version = 1\n").unwrap();
        seed_current_user_mutation_acl(&path);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(verify_manifest_security(
            &path,
            ManifestOwner::CurrentProcess,
            "styrn",
            &directory,
        )
        .is_err());

        harden_manifest_file(&path, ManifestOwner::CurrentProcess, "styrn").unwrap();
        verify_manifest_security(&path, ManifestOwner::CurrentProcess, "styrn", &directory)
            .unwrap();

        seed_current_user_mutation_acl(&directory);
        assert!(verify_manifest_security(
            &path,
            ManifestOwner::CurrentProcess,
            "styrn",
            &directory,
        )
        .is_err());
        harden_manifest_directory(&directory, ManifestOwner::CurrentProcess, "styrn").unwrap();
        verify_manifest_security(&path, ManifestOwner::CurrentProcess, "styrn", &directory)
            .unwrap();

        let _ = fs::remove_file(path);
        let _ = fs::remove_dir(directory);
    }

    #[test]
    fn user_trusted_root_accepts_protective_deny_acl_but_rejects_every_allow_acl() {
        let directory = std::env::temp_dir().join(format!(
            "styrn-macos-user-root-acl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();

        seed_current_user_acl(&directory, ACL_EXTENDED_DENY);
        verify_user_trusted_root(&directory).unwrap();

        seed_current_user_acl(&directory, ACL_EXTENDED_ALLOW);
        assert!(verify_user_trusted_root(&directory).is_err());

        clear_extended_acl(&directory).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn user_trusted_root_rejects_allow_acl_after_a_protective_deny_entry() {
        let directory = std::env::temp_dir().join(format!(
            "styrn-macos-user-root-multi-acl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        seed_current_user_acls(&directory, &[ACL_EXTENDED_DENY, ACL_EXTENDED_ALLOW]);

        assert!(verify_user_trusted_root(&directory).is_err());

        clear_extended_acl(&directory).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn native_application_support_is_an_accepted_user_receipt_trusted_root() {
        let root = Path::new(
            &std::env::var("HOME").expect("HOME is required for the macOS user-state contract"),
        )
        .join("Library/Application Support");

        verify_manifest_ancestors(&root, ManifestOwner::User, "", &root).unwrap();
    }

    fn seed_current_user_mutation_acl(path: &Path) {
        seed_current_user_acl(path, ACL_EXTENDED_ALLOW);
    }

    fn seed_current_user_acl(path: &Path, tag: i32) {
        seed_current_user_acls(path, &[tag]);
    }

    fn seed_current_user_acls(path: &Path, tags: &[i32]) {
        let mut acl = unsafe { acl_init(tags.len().try_into().unwrap()) };
        assert!(!acl.is_null());
        let mut uuid = [0_u8; 16];
        assert_eq!(
            unsafe { mbr_uid_to_uuid(libc::geteuid(), uuid.as_mut_ptr()) },
            0
        );
        for tag in tags {
            let mut entry = std::ptr::null_mut();
            assert_eq!(unsafe { acl_create_entry(&mut acl, &mut entry) }, 0);
            assert_eq!(unsafe { acl_set_tag_type(entry, *tag) }, 0);
            assert_eq!(unsafe { acl_set_qualifier(entry, uuid.as_ptr().cast()) }, 0);
            let mut permissions = std::ptr::null_mut();
            assert_eq!(unsafe { acl_get_permset(entry, &mut permissions) }, 0);
            assert_eq!(unsafe { acl_add_perm(permissions, ACL_WRITE_DATA) }, 0);
            assert_eq!(unsafe { acl_add_perm(permissions, ACL_DELETE) }, 0);
            assert_eq!(unsafe { acl_add_perm(permissions, ACL_DELETE_CHILD) }, 0);
        }
        let path = c_path(path).unwrap();
        assert_eq!(
            unsafe { acl_set_file(path.as_ptr(), ACL_TYPE_EXTENDED, acl) },
            0
        );
        unsafe {
            acl_free(acl);
        }
    }
}
