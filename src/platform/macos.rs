use super::{
    ManifestOwner, PrincipalKind, PrivateFileIdentity, SetupExecutionContext, SetupHostPrivilege,
    UnixCallerIds, WorkerPrincipal,
};
use std::ffi::{CString, OsString};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

type Acl = *mut std::ffi::c_void;
type AclEntry = *mut std::ffi::c_void;
#[cfg(test)]
type AclPermset = *mut std::ffi::c_void;
#[cfg(test)]
type AclFlagset = *mut std::ffi::c_void;

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
#[cfg(test)]
const ACL_ENTRY_FILE_INHERIT: i32 = 1 << 5;
#[cfg(test)]
const ACL_ENTRY_DIRECTORY_INHERIT: i32 = 1 << 6;

unsafe extern "C" {
    fn renamex_np(old: *const i8, new: *const i8, flags: u32) -> i32;
    fn acl_init(count: i32) -> Acl;
    fn acl_free(object: *mut std::ffi::c_void) -> i32;
    fn acl_get_file(path: *const i8, kind: i32) -> Acl;
    #[allow(dead_code)]
    fn acl_get_fd_np(fd: i32, kind: i32) -> Acl;
    fn acl_set_fd_np(fd: i32, acl: Acl, kind: i32) -> i32;
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
    fn acl_get_flagset_np(entry: AclEntry, flagset: *mut AclFlagset) -> i32;
    #[cfg(test)]
    fn acl_add_flag_np(flagset: AclFlagset, flag: i32) -> i32;
    #[cfg(test)]
    fn acl_set_flagset_np(entry: AclEntry, flagset: AclFlagset) -> i32;
    #[cfg(test)]
    fn mbr_uid_to_uuid(uid: u32, uuid: *mut u8) -> i32;
}

#[allow(dead_code)]
pub(crate) fn platform_name() -> &'static str {
    "macos"
}

pub(super) fn resolve_current_worker_principal() -> io::Result<WorkerPrincipal> {
    let real_uid = unsafe { libc::getuid() };
    let effective_uid = unsafe { libc::geteuid() };
    principal_for_uid(super::validate_unix_caller_ids(real_uid, effective_uid)?)
}

#[allow(dead_code)] // Consumed by the T0.14 setup action integration follow-up.
pub(super) fn default_worker_root(
    scope: super::InstallationScope,
    principal: &WorkerPrincipal,
) -> io::Result<(PathBuf, super::WorkerRootCreationPolicy)> {
    validate_worker_root_principal(scope, principal)?;
    match scope {
        super::InstallationScope::System => Ok((
            PathBuf::from("/Users/Shared/Styrn"),
            super::WorkerRootCreationPolicy::ExistingParent {
                allow_untrusted_parent_create: false,
            },
        )),
        super::InstallationScope::User => {
            let current = resolve_current_worker_principal()?;
            super::validate_user_scope_principal(principal, &current)?;
            let account = account_details_for_uid(principal.unix_uid()?)?;
            let home = PathBuf::from(account.home);
            Ok((
                home.join("Library/Application Support/Styrn"),
                super::WorkerRootCreationPolicy::CreateMissingFrom(home),
            ))
        }
    }
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
    let mut directory = creation_lock.try_clone()?;
    let mut root_disposition = None;
    for (index, component) in root_components[first_creatable..].iter().enumerate() {
        let is_root = first_creatable + index + 1 == root_components.len();
        let opened =
            open_or_create_worker_directory_at(&directory, component, true, expected_uid, is_root)?;
        if is_root {
            root_disposition = Some(opened.disposition);
        }
        directory = opened.directory;
    }
    let root_identity = worker_directory_identity(&directory)?;
    let root_observation = super::WorkerDirectoryNodeObservation::new(
        layout.root().to_path_buf(),
        root_disposition.expect("the normalized worker root has a leaf component"),
        root_identity,
    );

    let mut children = Vec::with_capacity(super::WorkerDirectoryLayout::child_names().len());
    for name in super::WorkerDirectoryLayout::child_names() {
        match open_worker_directory_at(&directory, name.as_bytes()) {
            Ok(child) => {
                verify_worker_directory_security(&child, expected_uid)?;
                children.push(Some(OpenedWorkerDirectory {
                    directory: child,
                    disposition: super::WorkerDirectoryNodeDisposition::Existing,
                }));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                children.push(None);
            }
            Err(error) => return Err(error),
        }
    }
    for (index, child) in children.iter_mut().enumerate() {
        if child.is_none() {
            *child = Some(open_or_create_worker_directory_at(
                &directory,
                super::WorkerDirectoryLayout::child_names()[index].as_bytes(),
                true,
                expected_uid,
                true,
            )?);
        }
    }

    if worker_directory_identity(&directory)? != root_identity {
        return Err(permission_denied(
            "worker root identity changed during layout creation",
        ));
    }
    verify_worker_path_identity(layout.root(), root_identity)?;
    let mut child_observations = Vec::with_capacity(children.len());
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
    }
    Ok(super::WorkerDirectoryCreation::new(
        root_observation,
        child_observations
            .try_into()
            .unwrap_or_else(|_| unreachable!("the worker layout always has exactly five children")),
    ))
}

struct OpenedWorkerDirectory {
    directory: std::fs::File,
    disposition: super::WorkerDirectoryNodeDisposition,
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
    parent: &std::fs::File,
    name: &[u8],
    may_create: bool,
    expected_uid: u32,
    existing_must_be_canonical: bool,
) -> io::Result<OpenedWorkerDirectory> {
    match open_worker_directory_at(parent, name) {
        Ok(directory) => {
            verify_existing_worker_directory(&directory, expected_uid, existing_must_be_canonical)?;
            return Ok(OpenedWorkerDirectory {
                directory,
                disposition: super::WorkerDirectoryNodeDisposition::Existing,
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && may_create => {}
        Err(error) => return Err(error),
    }
    let name = CString::new(name)
        .map_err(|_| invalid_data("worker directory component contains a NUL byte"))?;
    let created = if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == -1 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(worker_directory_open_error(error));
        }
        false
    } else {
        true
    };
    let directory = open_worker_directory_at(parent, name.to_bytes())?;
    if created {
        harden_new_worker_directory(&directory, expected_uid)?;
    } else {
        verify_existing_worker_directory(&directory, expected_uid, existing_must_be_canonical)?;
    }
    Ok(OpenedWorkerDirectory {
        directory,
        disposition: if created {
            super::WorkerDirectoryNodeDisposition::Created
        } else {
            super::WorkerDirectoryNodeDisposition::Existing
        },
    })
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
    let acl = unsafe { acl_init(0) };
    if acl.is_null() {
        return Err(io::Error::last_os_error());
    }
    let acl = OwnedAcl(acl);
    if unsafe { acl_set_fd_np(directory.as_raw_fd(), acl.0, ACL_TYPE_EXTENDED) } != 0 {
        return Err(io::Error::last_os_error());
    }
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
    verify_no_extended_acl_fd(directory.as_raw_fd())
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
        u64::try_from(status.st_dev)
            .map_err(|_| invalid_data("worker directory device identity is invalid"))?,
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
    if (status.st_uid != 0 && status.st_uid != expected_uid)
        || (status.st_mode & 0o022 != 0
            && !(status.st_uid == 0 && status.st_mode & libc::S_ISVTX != 0))
    {
        return Err(permission_denied(
            "worker root ancestor is controlled by an untrusted principal",
        ));
    }
    verify_no_extended_allow_acl_fd(directory.as_raw_fd())
        .map_err(|_| permission_denied("worker root ancestor has an untrusted extended ACL"))
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
    let account = account_details_for_uid(principal.unix_uid().unwrap()).unwrap();
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
    let account = account_details_for_uid(selected.uid)?;
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
    verify_no_extended_acl(path)
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
    let primary_group = i32::try_from(primary_gid)
        .map_err(|_| invalid_data("worker primary group is out of range"))?;
    let mut count = 16;
    let mut native_groups = vec![0_i32; count as usize];
    if unsafe {
        libc::getgrouplist(
            name.as_ptr(),
            primary_group,
            native_groups.as_mut_ptr(),
            &mut count,
        )
    } == -1
    {
        if !(17..=1024).contains(&count) {
            return Err(permission_denied(
                "worker supplementary group set is invalid",
            ));
        }
        native_groups.resize(count as usize, 0);
        if unsafe {
            libc::getgrouplist(
                name.as_ptr(),
                primary_group,
                native_groups.as_mut_ptr(),
                &mut count,
            )
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
    native_groups.truncate(count as usize);
    let mut groups = native_groups
        .into_iter()
        .map(|group| {
            libc::gid_t::try_from(group)
                .map_err(|_| invalid_data("worker supplementary group is out of range"))
        })
        .collect::<io::Result<Vec<_>>>()?;
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
            if requires_drop
                && (libc::setgroups(groups.len() as i32, groups.as_ptr()) != 0
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
    clear_extended_acl(path)?;
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
    clear_extended_acl(path)?;
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
    verify_file(path, owner, principal, 0o600, "private store file")?;
    verify_no_extended_acl(path)
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
        ManifestOwner::User => principal.unix_uid()?,
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
    verify_no_extended_acl_fd(parent.as_raw_fd())?;
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
        libc::renameatx_np(
            parent,
            removal.leaf.as_ptr(),
            parent,
            tombstone.as_ptr(),
            libc::RENAME_EXCL,
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
    verify_no_extended_acl(parent)?;
    verify_no_extended_acl(path)?;
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
    worker: &WorkerPrincipal,
) -> io::Result<()> {
    verify_directory(directory, owner, worker)
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
    verify_user_trusted_root_chain(trusted_root, current_uid)
}

fn verify_user_trusted_root_chain(path: &Path, current_uid: u32) -> io::Result<()> {
    verify_user_trusted_root(path, current_uid)?;
    let metadata = fs::metadata(path)?;
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

fn verify_user_trusted_root(path: &Path, current_uid: u32) -> io::Result<()> {
    require_real_directory(path)?;
    verify_trusted_root_has_no_extended_allow_acl(path)?;
    let metadata = fs::metadata(path)?;
    if metadata.uid() != current_uid || metadata.mode() & 0o022 != 0 {
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
    verify_no_extended_allow_acl_value(acl)
}

fn verify_no_extended_allow_acl_fd(fd: i32) -> io::Result<()> {
    verify_no_extended_allow_acl_value(unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) })
}

fn verify_no_extended_allow_acl_value(acl: Acl) -> io::Result<()> {
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
    verify_no_extended_acl(path)?;
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
    verify_no_extended_acl(path)?;
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

    fn test_principal() -> WorkerPrincipal {
        resolve_current_worker_principal().unwrap()
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
    fn existing_acl_bearing_canonical_worker_root_is_rejected_without_rewrite() {
        let principal = test_principal();
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-existing-acl-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        let root = parent.join("root");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        seed_current_user_acl(&root, ACL_EXTENDED_ALLOW);
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::System,
            &principal,
            Some(&root),
        )
        .unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(verify_no_extended_acl(&root).is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        clear_extended_acl(&root).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn user_profile_anchor_with_mutating_allow_acl_is_rejected_before_creation() {
        let principal = test_principal();
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-profile-acl-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        let profile = parent.join("profile");
        fs::create_dir_all(&profile).unwrap();
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o700)).unwrap();
        seed_current_user_acl(&profile, ACL_EXTENDED_ALLOW);
        let root = profile.join("Library/Application Support/Styrn");
        let layout = crate::platform::WorkerDirectoryLayout::new(
            root,
            crate::platform::WorkerRootCreationPolicy::CreateMissingFrom(profile.clone()),
            principal,
        );

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!profile.join("Library").exists());
        assert!(verify_no_extended_acl(&profile).is_err());
        clear_extended_acl(&profile).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn new_worker_nodes_clear_inherited_extended_acl_before_descending() {
        let principal = test_principal();
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-inherited-acl-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        let profile = parent.join("profile");
        fs::create_dir_all(&profile).unwrap();
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o700)).unwrap();
        seed_current_user_acl_with_flags_and_permissions(
            &profile,
            ACL_EXTENDED_DENY,
            &[ACL_ENTRY_FILE_INHERIT, ACL_ENTRY_DIRECTORY_INHERIT],
            &[ACL_WRITE_DATA],
        );
        let inheritance_probe = profile.join("inheritance-probe");
        fs::create_dir(&inheritance_probe).unwrap();
        assert!(verify_no_extended_acl(&inheritance_probe).is_err());
        clear_extended_acl(&inheritance_probe).unwrap();
        fs::remove_dir(&inheritance_probe).unwrap();
        let root = profile.join("Library/Application Support/Styrn");
        let layout = crate::platform::WorkerDirectoryLayout::new(
            root.clone(),
            crate::platform::WorkerRootCreationPolicy::CreateMissingFrom(profile.clone()),
            principal,
        );

        create_worker_directory_layout(&layout).unwrap();

        for path in [
            profile.join("Library"),
            profile.join("Library/Application Support"),
            root.clone(),
            root.join("repos"),
            root.join("jobs"),
            root.join("cache"),
            root.join("artifacts"),
            root.join("logs"),
        ] {
            verify_no_extended_acl(&path).unwrap();
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert!(verify_no_extended_acl(&profile).is_err());
        clear_extended_acl(&profile).unwrap();
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
            &test_principal(),
            &directory,
        )
        .is_err());

        harden_manifest_file(&path, ManifestOwner::CurrentProcess, &test_principal()).unwrap();
        verify_manifest_security(
            &path,
            ManifestOwner::CurrentProcess,
            &test_principal(),
            &directory,
        )
        .unwrap();

        seed_current_user_mutation_acl(&directory);
        assert!(verify_manifest_security(
            &path,
            ManifestOwner::CurrentProcess,
            &test_principal(),
            &directory,
        )
        .is_err());
        harden_manifest_directory(&directory, ManifestOwner::CurrentProcess, &test_principal())
            .unwrap();
        verify_manifest_security(
            &path,
            ManifestOwner::CurrentProcess,
            &test_principal(),
            &directory,
        )
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
        verify_user_trusted_root(&directory, unsafe { libc::geteuid() }).unwrap();

        seed_current_user_acl(&directory, ACL_EXTENDED_ALLOW);
        assert!(verify_user_trusted_root(&directory, unsafe { libc::geteuid() }).is_err());

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

        assert!(verify_user_trusted_root(&directory, unsafe { libc::geteuid() }).is_err());

        clear_extended_acl(&directory).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn native_application_support_is_an_accepted_user_receipt_trusted_root() {
        let root = Path::new(
            &std::env::var("HOME").expect("HOME is required for the macOS user-state contract"),
        )
        .join("Library/Application Support");

        verify_manifest_ancestors(&root, ManifestOwner::User, &test_principal(), &root).unwrap();
    }

    fn seed_current_user_mutation_acl(path: &Path) {
        seed_current_user_acl(path, ACL_EXTENDED_ALLOW);
    }

    fn seed_current_user_acl(path: &Path, tag: i32) {
        seed_current_user_acls(path, &[tag]);
    }

    fn seed_current_user_acl_with_flags_and_permissions(
        path: &Path,
        tag: i32,
        flags: &[i32],
        permissions: &[i32],
    ) {
        seed_current_user_acls_with_flags(path, &[tag], flags, permissions);
    }

    fn seed_current_user_acls(path: &Path, tags: &[i32]) {
        seed_current_user_acls_with_flags(
            path,
            tags,
            &[],
            &[ACL_WRITE_DATA, ACL_DELETE, ACL_DELETE_CHILD],
        );
    }

    fn seed_current_user_acls_with_flags(
        path: &Path,
        tags: &[i32],
        flags: &[i32],
        acl_permissions: &[i32],
    ) {
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
            for permission in acl_permissions {
                assert_eq!(unsafe { acl_add_perm(permissions, *permission) }, 0);
            }
            let mut flagset = std::ptr::null_mut();
            assert_eq!(unsafe { acl_get_flagset_np(entry, &mut flagset) }, 0);
            for flag in flags {
                assert_eq!(unsafe { acl_add_flag_np(flagset, *flag) }, 0);
            }
            assert_eq!(unsafe { acl_set_flagset_np(entry, flagset) }, 0);
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
