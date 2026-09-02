use super::{
    ManifestOwner, PrincipalKind, PrivateFileIdentity, SetupExecutionContext, SetupHostPrivilege,
    UnixCallerIds, WorkerPrincipal,
};
use std::ffi::{CString, OsString};
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;

#[allow(dead_code)]
pub(crate) fn platform_name() -> &'static str {
    "linux"
}

pub(super) fn resolve_current_worker_principal() -> io::Result<WorkerPrincipal> {
    let real_uid = unsafe { libc::getuid() };
    let effective_uid = unsafe { libc::geteuid() };
    principal_for_uid(super::validate_unix_caller_ids(real_uid, effective_uid)?)
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
    let account = account_details_for_uid(principal.unix_uid().unwrap()).unwrap();
    UserExecutionToken {
        uid: principal.unix_uid().unwrap(),
        gid: account.gid,
        supplementary_groups: supplementary_groups(principal.name(), account.gid).unwrap(),
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
    let account = account_details_for_uid(selected.uid)?;
    if account.gid != selected.gid
        || (selected.privilege == SetupHostPrivilege::Root
            && original_name.as_deref() != Some(account.principal.name()))
    {
        return Err(permission_denied(
            "sudo original uid, gid, and account name do not identify one native user",
        ));
    }
    Ok(SetupExecutionContext::new(
        selected.privilege,
        account.principal.clone(),
        UserExecutionToken {
            uid: selected.uid,
            gid: selected.gid,
            supplementary_groups: supplementary_groups(account.principal.name(), account.gid)?,
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
) -> io::Result<()> {
    let current = std::env::current_exe()?;
    let executable = super::verify_setup_authorization_executable(executable)?;
    let invocation =
        super::unix_authorization_invocation(&executable, request_path, request_digest, &current)?;
    let status = std::process::Command::new(invocation.program)
        .args(invocation.arguments)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(permission_denied(
            "native setup authorization was declined or failed",
        ))
    }
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
pub(super) fn resolve_named_worker_principal(name: &str) -> io::Result<WorkerPrincipal> {
    let uid = lookup_worker_uid(name)?;
    let principal = principal_for_uid(uid)?;
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
    let current = principal_for_uid(principal.unix_uid()?)?;
    if &current != principal {
        return Err(permission_denied("worker uid/name identity drift detected"));
    }
    Ok(())
}

fn principal_for_uid(uid: u32) -> io::Result<WorkerPrincipal> {
    account_for_uid(uid).map(|(principal, _)| principal)
}

fn account_for_uid(uid: u32) -> io::Result<(WorkerPrincipal, u32)> {
    let account = account_details_for_uid(uid)?;
    Ok((account.principal, account.gid))
}

struct UnixAccountDetails {
    principal: WorkerPrincipal,
    gid: u32,
    home: OsString,
}

fn account_details_for_uid(uid: u32) -> io::Result<UnixAccountDetails> {
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
    if result.is_null() || entry.pw_name.is_null() || entry.pw_dir.is_null() {
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
    if !Path::new(&home).is_absolute() {
        return Err(invalid_data("worker home directory is not absolute"));
    }
    Ok(UnixAccountDetails {
        principal: WorkerPrincipal::new(PrincipalKind::UnixUid, uid.to_string(), name)?,
        gid: entry.pw_gid,
        home,
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
    groups.sort_unstable();
    groups.dedup();
    if !groups.contains(&primary_gid) {
        groups.push(primary_gid);
        groups.sort_unstable();
    }
    Ok(groups)
}

fn validate_user_execution_token(token: &UserExecutionToken) -> io::Result<()> {
    if token.uid == 0
        || token.name.is_empty()
        || !Path::new(&token.home).is_absolute()
        || token.supplementary_groups.is_empty()
        || !token.supplementary_groups.contains(&token.gid)
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
    if token.requires_drop {
        let uid = token.uid;
        let gid = token.gid;
        let groups = token.supplementary_groups.clone();
        unsafe {
            command.pre_exec(move || {
                if libc::setgroups(groups.len(), groups.as_ptr()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0
                    || libc::getuid() != uid
                    || libc::geteuid() != uid
                    || libc::getgid() != gid
                    || libc::getegid() != gid
                    || libc::setegid(0) == 0
                    || libc::seteuid(0) == 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
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
        || parent_metadata.mode() & 0o077 != 0
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
