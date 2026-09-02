#[allow(dead_code)]
pub(crate) fn platform_name() -> &'static str {
    "windows"
}

use super::ManifestOwner;
use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
const SE_DACL_PROTECTED: u16 = 0x1000;
const SE_FILE_OBJECT: u32 = 1;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const WIN_LOCAL_SYSTEM_SID: i32 = 22;
const WIN_BUILTIN_ADMINISTRATORS_SID: i32 = 26;
const FILE_READ: u32 = 0x0012_0089;
const FILE_EXECUTE: u32 = 0x0000_0020;
const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const OBJECT_INHERIT_ACE: u8 = 0x01;
const CONTAINER_INHERIT_ACE: u8 = 0x02;
const INHERIT_ONLY_ACE: u8 = 0x08;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const INVALID_FILE_ATTRIBUTES: u32 = 0xffff_ffff;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const CREATE_NEW: u32 = 1;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const PARENT_TAKEOVER_ACCESS: u32 =
    0x0000_0040 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x4000_0000 | 0x1000_0000;

#[repr(C)]
struct Acl {
    revision: u8,
    sbz1: u8,
    size: u16,
    ace_count: u16,
    sbz2: u16,
}

#[repr(C)]
struct AceHeader {
    kind: u8,
    flags: u8,
    size: u16,
}

#[repr(C)]
struct AccessAllowedAce {
    header: AceHeader,
    mask: u32,
    sid_start: u32,
}

#[derive(Clone, Copy)]
enum AclKind {
    Manifest,
    Directory,
    Lock,
    Staging,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Principal {
    System,
    Administrators,
    Worker,
    Unexpected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AceInspection {
    principal: Principal,
    mask: u32,
    flags: u8,
    allowed: bool,
}

struct AclInspection {
    owner_is_administrators: bool,
    dacl_is_protected: bool,
    entries: Vec<AceInspection>,
}

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    security_descriptor: *mut c_void,
    inherit_handle: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FileTime {
    low_date_time: u32,
    high_date_time: u32,
}

#[repr(C)]
struct ByHandleFileInformation {
    file_attributes: u32,
    creation_time: FileTime,
    last_access_time: FileTime,
    last_write_time: FileTime,
    volume_serial_number: u32,
    file_size_high: u32,
    file_size_low: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        security_descriptor: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
    fn SetFileSecurityW(
        file_name: *const u16,
        security_information: u32,
        security_descriptor: *const c_void,
    ) -> i32;
    fn LookupAccountNameW(
        system_name: *const u16,
        account_name: *const u16,
        sid: *mut c_void,
        sid_size: *mut u32,
        referenced_domain_name: *mut u16,
        domain_size: *mut u32,
        sid_name_use: *mut i32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *const c_void, string_sid: *mut *mut u16) -> i32;
    fn GetNamedSecurityInfoW(
        object_name: *mut u16,
        object_type: u32,
        security_information: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut Acl,
        sacl: *mut *mut Acl,
        security_descriptor: *mut *mut c_void,
    ) -> u32;
    fn GetSecurityInfo(
        handle: *mut c_void,
        object_type: u32,
        security_information: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut Acl,
        sacl: *mut *mut Acl,
        security_descriptor: *mut *mut c_void,
    ) -> u32;
    fn GetSecurityDescriptorControl(
        security_descriptor: *const c_void,
        control: *mut u16,
        revision: *mut u32,
    ) -> i32;
    fn GetAce(acl: *const Acl, index: u32, ace: *mut *mut c_void) -> i32;
    fn CreateWellKnownSid(
        sid_type: i32,
        domain_sid: *const c_void,
        sid: *mut c_void,
        sid_size: *mut u32,
    ) -> i32;
    fn EqualSid(first: *const c_void, second: *const c_void) -> i32;
    #[cfg(test)]
    fn LogonUserW(
        username: *const u16,
        domain: *const u16,
        password: *const u16,
        logon_type: u32,
        provider: u32,
        token: *mut *mut c_void,
    ) -> i32;
    #[cfg(test)]
    fn ImpersonateLoggedOnUser(token: *mut c_void) -> i32;
    #[cfg(test)]
    fn RevertToSelf() -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
    fn GetFileAttributesW(file_name: *const u16) -> u32;
    fn CreateDirectoryW(
        path_name: *const u16,
        security_attributes: *const SecurityAttributes,
    ) -> i32;
    fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *const SecurityAttributes,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: *mut c_void,
    ) -> *mut c_void;
    fn GetFileInformationByHandle(
        file: *mut c_void,
        information: *mut ByHandleFileInformation,
    ) -> i32;
    fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
    #[cfg(test)]
    fn CloseHandle(handle: *mut c_void) -> i32;
}

pub(super) fn create_private_manifest_staging_directory(
    path: &Path,
    owner: ManifestOwner,
) -> io::Result<()> {
    if is_test_owner(owner) {
        return std::fs::create_dir(path);
    }

    let wide_sddl = wide(&acl_sddl("unused", AclKind::Staging));
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = LocalAllocation(descriptor);
    let attributes = SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        security_descriptor: descriptor.0,
        inherit_handle: 0,
    };
    let path = wide_os(path);
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn replace_file(temporary: &Path, destination: &Path) -> io::Result<()> {
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

    let existing: Vec<u16> = temporary
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let replacement: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    if unsafe {
        MoveFileExW(
            existing.as_ptr(),
            replacement.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn publish_manifest_directory(staging: &Path, destination: &Path) -> io::Result<()> {
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    require_kind(staging, true)?;
    let staging = wide_os(staging);
    let destination_path = destination;
    let destination = wide_os(destination);
    if unsafe {
        MoveFileExW(
            staging.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } != 0
    {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if std::fs::symlink_metadata(destination_path).is_ok() {
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "manifest destination already exists",
        ))
    } else {
        Err(error)
    }
}

pub(super) fn harden_manifest_directory(
    path: &Path,
    owner: ManifestOwner,
    worker: &str,
) -> io::Result<()> {
    require_kind(path, true)?;
    if is_test_owner(owner) {
        return Ok(());
    }
    apply_acl(path, worker, AclKind::Directory)?;
    inspect_acl(path, worker, AclKind::Directory)
}

pub(super) fn harden_manifest_file(
    path: &Path,
    owner: ManifestOwner,
    worker: &str,
) -> io::Result<()> {
    require_kind(path, false)?;
    if is_test_owner(owner) {
        return Ok(());
    }
    apply_acl(path, worker, AclKind::Manifest)?;
    inspect_acl(path, worker, AclKind::Manifest)
}

pub(super) fn open_manifest_lock(path: &Path, owner: ManifestOwner) -> io::Result<std::fs::File> {
    let created = create_private_file_with_sharing(
        path,
        owner,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    );
    let file = match created {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            verify_private_file_security(path, owner)?;
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?
        }
        Err(error) => return Err(error),
    };
    verify_private_file_security(path, owner)?;
    Ok(file)
}

pub(super) fn verify_private_file_security(path: &Path, owner: ManifestOwner) -> io::Result<()> {
    require_kind(path, false)?;
    if is_test_owner(owner) {
        return Ok(());
    }
    inspect_private_acl(path, AclKind::Lock)
}

pub(super) fn create_private_file(path: &Path, owner: ManifestOwner) -> io::Result<std::fs::File> {
    create_private_file_with_sharing(
        path,
        owner,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
}

fn create_private_file_with_sharing(
    path: &Path,
    owner: ManifestOwner,
    share_mode: u32,
) -> io::Result<std::fs::File> {
    if is_test_owner(owner) {
        use std::os::windows::fs::OpenOptionsExt;
        return std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(share_mode)
            .open(path);
    }

    let wide_sddl = wide(&acl_sddl("unused", AclKind::Lock));
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = LocalAllocation(descriptor);
    let attributes = SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        security_descriptor: descriptor.0,
        inherit_handle: 0,
    };
    let path = wide_os(path);
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            share_mode,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle as isize == -1 {
        return Err(io::Error::last_os_error());
    }
    use std::os::windows::io::FromRawHandle;
    Ok(unsafe { std::fs::File::from_raw_handle(handle) })
}

pub(super) fn verify_manifest_security(
    path: &Path,
    owner: ManifestOwner,
    worker: &str,
    trusted_root: &Path,
) -> io::Result<()> {
    require_kind(path, false)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("manifest path has no parent directory"))?;
    require_kind(parent, true)?;
    if is_test_owner(owner) {
        return Ok(());
    }
    verify_manifest_ancestors(parent, owner, worker, trusted_root)?;
    inspect_acl(parent, worker, AclKind::Directory)?;
    inspect_acl(path, worker, AclKind::Manifest)
}

pub(super) fn open_verified_manifest_file_for_read(
    path: &Path,
    owner: ManifestOwner,
    worker: &str,
    trusted_root: &Path,
) -> io::Result<std::fs::File> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};

    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("manifest path has no parent directory"))?;
    require_kind(parent, true)?;
    verify_manifest_ancestors(parent, owner, worker, trusted_root)?;
    if !is_test_owner(owner) {
        inspect_acl(parent, worker, AclKind::Directory)?;
    }
    let path = wide_os(path);
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle as isize == -1 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { std::fs::File::from_raw_handle(handle) };
    let mut information = unsafe { std::mem::zeroed::<ByHandleFileInformation>() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if information.file_attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
    {
        return Err(permission_denied("manifest target is not a regular file"));
    }
    if !is_test_owner(owner) {
        inspect_handle_acl(&file, worker, AclKind::Manifest)?;
        verify_manifest_ancestors(parent, owner, worker, trusted_root)?;
        inspect_acl(parent, worker, AclKind::Directory)?;
    }
    Ok(file)
}

pub(super) fn verify_manifest_file_target(path: &Path) -> io::Result<()> {
    require_kind(path, false)
}

pub(super) fn verify_manifest_directory_security(
    directory: &Path,
    owner: ManifestOwner,
    worker: &str,
) -> io::Result<()> {
    require_kind(directory, true)?;
    if is_test_owner(owner) {
        return Ok(());
    }
    inspect_acl(directory, worker, AclKind::Directory)
}

pub(super) fn verify_manifest_parent_chain(
    parent: &Path,
    owner: ManifestOwner,
    worker: &str,
) -> io::Result<()> {
    let mut current = Some(parent);
    while let Some(ancestor) = current {
        require_kind(ancestor, true)?;
        if !is_test_owner(owner) {
            inspect_ancestor_acl(ancestor, worker)?;
        }
        current = ancestor.parent();
    }
    Ok(())
}

pub(super) fn verify_manifest_ancestors(
    directory: &Path,
    owner: ManifestOwner,
    worker: &str,
    trusted_root: &Path,
) -> io::Result<()> {
    let system_owner = !is_test_owner(owner);
    if (system_owner && directory != trusted_root)
        || (!system_owner && !directory.starts_with(trusted_root))
    {
        return Err(permission_denied(
            "manifest directory is outside its trusted root",
        ));
    }
    if !system_owner && (directory == trusted_root || is_test_owner(owner)) {
        return require_kind(directory, true);
    }
    require_kind(directory, true)?;
    let mut current = directory.parent();
    while let Some(ancestor) = current {
        require_kind(ancestor, true)?;
        inspect_ancestor_acl(ancestor, worker)?;
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

fn is_test_owner(owner: ManifestOwner) -> bool {
    match owner {
        ManifestOwner::System => false,
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => true,
    }
}

fn apply_acl(path: &Path, worker: &str, kind: AclKind) -> io::Result<()> {
    let worker_sid = lookup_account_sid(worker)?;
    let worker_sid_string = sid_to_string(worker_sid.as_ptr().cast())?;
    let sddl = acl_sddl(&worker_sid_string, kind);
    apply_sddl(path, &sddl)
}

fn apply_sddl(path: &Path, sddl: &str) -> io::Result<()> {
    let wide_sddl = wide(sddl);
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = LocalAllocation(descriptor);
    let wide_path = wide_os(path);
    if unsafe {
        SetFileSecurityW(
            wide_path.as_ptr(),
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn acl_sddl(worker_sid: &str, kind: AclKind) -> String {
    match kind {
        AclKind::Manifest => {
            format!("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;{worker_sid})")
        }
        AclKind::Directory => {
            format!("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;{worker_sid})")
        }
        AclKind::Lock | AclKind::Staging => "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)".to_owned(),
    }
}

fn inspect_acl(path: &Path, worker: &str, kind: AclKind) -> io::Result<()> {
    let worker = lookup_account_sid(worker)?;
    inspect_acl_with_worker(path, &worker, kind)
}

fn inspect_private_acl(path: &Path, kind: AclKind) -> io::Result<()> {
    // Private lock/temporary/intent ACLs contain only SYSTEM and
    // Administrators, so verification must not depend on any worker identity.
    let non_worker = well_known_sid(WIN_LOCAL_SYSTEM_SID)?;
    inspect_acl_with_worker(path, &non_worker, kind)
}

fn inspect_acl_with_worker(path: &Path, worker: &[u8], kind: AclKind) -> io::Result<()> {
    let mut path = wide_os(path);
    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path.as_mut_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let descriptor = LocalAllocation(descriptor);
    inspect_security_descriptor(owner, dacl, descriptor.0, worker, kind)
}

fn inspect_handle_acl(file: &std::fs::File, worker: &str, kind: AclKind) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    let worker = lookup_account_sid(worker)?;
    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let descriptor = LocalAllocation(descriptor);
    inspect_security_descriptor(owner, dacl, descriptor.0, &worker, kind)
}

fn inspect_security_descriptor(
    owner: *mut c_void,
    dacl: *mut Acl,
    descriptor: *mut c_void,
    worker: &[u8],
    kind: AclKind,
) -> io::Result<()> {
    if dacl.is_null() || owner.is_null() {
        return Err(permission_denied(
            "manifest security descriptor is incomplete",
        ));
    }

    let administrators = well_known_sid(WIN_BUILTIN_ADMINISTRATORS_SID)?;
    let system = well_known_sid(WIN_LOCAL_SYSTEM_SID)?;
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let inspection = AclInspection {
        owner_is_administrators: unsafe { EqualSid(owner, administrators.as_ptr().cast()) } != 0,
        dacl_is_protected: control & SE_DACL_PROTECTED != 0,
        entries: inspect_aces(dacl, &system, &administrators, worker)?,
    };
    validate_acl_contract(&inspection, kind)
}

fn inspect_ancestor_acl(path: &Path, worker: &str) -> io::Result<()> {
    let mut path = wide_os(path);
    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path.as_mut_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _descriptor = LocalAllocation(descriptor);
    if dacl.is_null() || owner.is_null() {
        return Err(permission_denied(
            "manifest ancestor security descriptor is incomplete",
        ));
    }
    let administrators = well_known_sid(WIN_BUILTIN_ADMINISTRATORS_SID)?;
    let system = well_known_sid(WIN_LOCAL_SYSTEM_SID)?;
    let worker = lookup_account_sid(worker)?;
    validate_ancestor_entries(
        unsafe { EqualSid(owner, worker.as_ptr().cast()) } != 0,
        &inspect_aces(dacl, &system, &administrators, &worker)?,
    )
}

fn validate_ancestor_entries(worker_is_owner: bool, entries: &[AceInspection]) -> io::Result<()> {
    if worker_is_owner {
        return Err(permission_denied(
            "configured worker owns a manifest ancestor",
        ));
    }
    for entry in entries {
        let applies_here = entry.flags & INHERIT_ONLY_ACE == 0;
        let trusted_principal = matches!(
            entry.principal,
            Principal::System | Principal::Administrators
        );
        if entry.allowed
            && applies_here
            && !trusted_principal
            && entry.mask & PARENT_TAKEOVER_ACCESS != 0
        {
            return Err(permission_denied(
                "manifest ancestor grants delete-child or ACL takeover access",
            ));
        }
    }
    Ok(())
}

fn validate_acl_contract(inspection: &AclInspection, kind: AclKind) -> io::Result<()> {
    if !inspection.owner_is_administrators {
        return Err(permission_denied(
            "manifest ACL owner must be Administrators",
        ));
    }
    if !inspection.dacl_is_protected {
        return Err(permission_denied(
            "manifest DACL must be protected from inherited grants",
        ));
    }
    let inherited_flags = if matches!(kind, AclKind::Directory) {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };
    let mut expected = vec![
        AceInspection {
            principal: Principal::System,
            mask: FILE_ALL_ACCESS,
            flags: inherited_flags,
            allowed: true,
        },
        AceInspection {
            principal: Principal::Administrators,
            mask: FILE_ALL_ACCESS,
            flags: inherited_flags,
            allowed: true,
        },
    ];
    match kind {
        AclKind::Manifest => expected.push(AceInspection {
            principal: Principal::Worker,
            mask: FILE_READ,
            flags: 0,
            allowed: true,
        }),
        AclKind::Directory => expected.push(AceInspection {
            principal: Principal::Worker,
            mask: FILE_READ | FILE_EXECUTE,
            flags: inherited_flags,
            allowed: true,
        }),
        AclKind::Lock | AclKind::Staging => {}
    }
    if inspection.entries.len() != expected.len()
        || expected
            .iter()
            .any(|entry| !inspection.entries.contains(entry))
    {
        return Err(permission_denied(
            "manifest DACL does not match the exact principal and rights contract",
        ));
    }
    Ok(())
}

fn inspect_aces(
    acl: *const Acl,
    system: &[u8],
    administrators: &[u8],
    worker: &[u8],
) -> io::Result<Vec<AceInspection>> {
    let mut entries = Vec::with_capacity(unsafe { (*acl).ace_count as usize });
    for index in 0..unsafe { (*acl).ace_count as u32 } {
        let mut raw = std::ptr::null_mut();
        if unsafe { GetAce(acl, index, &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let header = unsafe { &*raw.cast::<AceHeader>() };
        if !matches!(
            header.kind,
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE
        ) {
            entries.push(AceInspection {
                principal: Principal::Unexpected,
                mask: PARENT_TAKEOVER_ACCESS,
                flags: header.flags,
                allowed: true,
            });
            continue;
        }
        let ace = unsafe { &*raw.cast::<AccessAllowedAce>() };
        let sid = std::ptr::addr_of!(ace.sid_start).cast::<c_void>();
        let principal = if unsafe { EqualSid(sid, system.as_ptr().cast()) } != 0 {
            Principal::System
        } else if unsafe { EqualSid(sid, administrators.as_ptr().cast()) } != 0 {
            Principal::Administrators
        } else if unsafe { EqualSid(sid, worker.as_ptr().cast()) } != 0 {
            Principal::Worker
        } else {
            Principal::Unexpected
        };
        entries.push(AceInspection {
            principal,
            mask: ace.mask,
            flags: ace.header.flags,
            allowed: ace.header.kind == ACCESS_ALLOWED_ACE_TYPE,
        });
    }
    Ok(entries)
}

fn lookup_account_sid(account: &str) -> io::Result<Vec<u8>> {
    let account = wide(account);
    let mut sid_size = 0;
    let mut domain_size = 0;
    let mut sid_use = 0;
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            std::ptr::null_mut(),
            &mut sid_size,
            std::ptr::null_mut(),
            &mut domain_size,
            &mut sid_use,
        );
    }
    if io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(io::Error::last_os_error());
    }
    let mut sid = vec![0_u8; sid_size as usize];
    let mut domain = vec![0_u16; domain_size as usize];
    if unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut sid_use,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(sid)
}

fn well_known_sid(kind: i32) -> io::Result<Vec<u8>> {
    let mut size = 68;
    let mut sid = vec![0_u8; size as usize];
    if unsafe { CreateWellKnownSid(kind, std::ptr::null(), sid.as_mut_ptr().cast(), &mut size) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    sid.truncate(size as usize);
    Ok(sid)
}

fn sid_to_string(sid: *const c_void) -> io::Result<String> {
    let mut string = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut string) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let string = LocalWideString(string);
    let length = (0..)
        .take_while(|&index| unsafe { *string.0.add(index) } != 0)
        .count();
    String::from_utf16(unsafe { std::slice::from_raw_parts(string.0, length) })
        .map_err(|_| invalid_data("Windows returned a non-UTF-16 SID string"))
}

fn require_kind(path: &Path, directory: bool) -> io::Result<()> {
    let wide_path = wide_os(path);
    let attributes = unsafe { GetFileAttributesW(wide_path.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        return Err(io::Error::last_os_error());
    }
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(permission_denied(
            "manifest security path crosses a reparse point",
        ));
    }
    let metadata = std::fs::symlink_metadata(path)?;
    let valid = if directory {
        metadata.file_type().is_dir()
    } else {
        metadata.file_type().is_file()
    };
    if !valid {
        return Err(invalid_data("manifest ACL target has the wrong file type"));
    }
    Ok(())
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_os(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn permission_denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.to_owned())
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

struct LocalWideString(*mut u16);

impl Drop for LocalWideString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0.cast());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructed_acl_is_protected_and_grants_only_the_documented_principals() {
        assert_eq!(
            acl_sddl("S-1-5-21-1-2-3-1001", AclKind::Manifest),
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;S-1-5-21-1-2-3-1001)"
        );
        assert_eq!(
            acl_sddl("S-1-5-21-1-2-3-1001", AclKind::Directory),
            "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-21-1-2-3-1001)"
        );
        assert_eq!(
            acl_sddl("S-1-5-21-1-2-3-1001", AclKind::Staging),
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
        );
        assert_eq!(
            acl_sddl("worker-is-deliberately-unused", AclKind::Lock),
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
        );
    }

    #[test]
    fn private_staging_acl_rejects_worker_inheritance_and_unexpected_principals() {
        let base = AclInspection {
            owner_is_administrators: true,
            dacl_is_protected: true,
            entries: vec![
                AceInspection {
                    principal: Principal::System,
                    mask: FILE_ALL_ACCESS,
                    flags: 0,
                    allowed: true,
                },
                AceInspection {
                    principal: Principal::Administrators,
                    mask: FILE_ALL_ACCESS,
                    flags: 0,
                    allowed: true,
                },
            ],
        };
        assert!(validate_acl_contract(&base, AclKind::Staging).is_ok());
        for principal in [Principal::Worker, Principal::Unexpected] {
            let mut entries = base.entries.clone();
            entries.push(AceInspection {
                principal,
                mask: FILE_ALL_ACCESS,
                flags: OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                allowed: true,
            });
            assert!(validate_acl_contract(
                &AclInspection {
                    owner_is_administrators: true,
                    dacl_is_protected: true,
                    entries,
                },
                AclKind::Staging,
            )
            .is_err());
        }
    }

    #[test]
    fn inspection_rejects_inherited_or_explicit_worker_mutation_rights() {
        let inherited_write = AclInspection {
            owner_is_administrators: true,
            dacl_is_protected: false,
            entries: manifest_entries(),
        };
        assert!(validate_acl_contract(&inherited_write, AclKind::Manifest).is_err());

        let mut explicit_entries = manifest_entries();
        explicit_entries[2].mask |= 0x2;
        let explicit_write = AclInspection {
            owner_is_administrators: true,
            dacl_is_protected: true,
            entries: explicit_entries,
        };
        assert!(validate_acl_contract(&explicit_write, AclKind::Manifest).is_err());
    }

    #[test]
    fn inspection_rejects_users_authenticated_users_and_unexpected_principals() {
        for mask in [FILE_READ, FILE_READ | 0x2, FILE_ALL_ACCESS] {
            let mut entries = manifest_entries();
            entries.push(AceInspection {
                principal: Principal::Unexpected,
                mask,
                flags: 0,
                allowed: true,
            });
            assert!(validate_acl_contract(
                &AclInspection {
                    owner_is_administrators: true,
                    dacl_is_protected: true,
                    entries,
                },
                AclKind::Manifest,
            )
            .is_err());
        }
    }

    #[test]
    fn ancestor_rejects_worker_or_group_delete_child_and_acl_takeover() {
        for mask in [0x40, 0x0001_0000, 0x0004_0000, 0x0008_0000, 0x1000_0000] {
            for principal in [Principal::Worker, Principal::Unexpected] {
                assert!(validate_ancestor_entries(
                    false,
                    &[AceInspection {
                        principal,
                        mask,
                        flags: 0,
                        allowed: true,
                    }]
                )
                .is_err());
            }
        }
        assert!(validate_ancestor_entries(true, &[]).is_err());
        assert!(validate_ancestor_entries(
            false,
            &[AceInspection {
                principal: Principal::Unexpected,
                mask: 0x40,
                flags: INHERIT_ONLY_ACE,
                allowed: true,
            }]
        )
        .is_ok());
    }

    #[test]
    fn inspection_accepts_exact_read_only_worker_contract() {
        assert!(validate_acl_contract(
            &AclInspection {
                owner_is_administrators: true,
                dacl_is_protected: true,
                entries: manifest_entries(),
            },
            AclKind::Manifest,
        )
        .is_ok());
    }

    #[test]
    fn private_file_can_be_atomically_published_while_its_handle_remains_open() {
        let root = std::env::temp_dir().join(format!(
            "styrn-private-file-publication-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let temporary = root.join("temporary");
        let destination = root.join("destination");
        let mut file = create_private_file(&temporary, ManifestOwner::CurrentProcess).unwrap();
        std::io::Write::write_all(&mut file, b"complete").unwrap();
        file.sync_all().unwrap();

        replace_file(&temporary, &destination).unwrap();

        assert_eq!(std::fs::read(&destination).unwrap(), b"complete");
        drop(file);
        std::fs::remove_file(destination).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    fn manifest_entries() -> Vec<AceInspection> {
        vec![
            AceInspection {
                principal: Principal::System,
                mask: FILE_ALL_ACCESS,
                flags: 0,
                allowed: true,
            },
            AceInspection {
                principal: Principal::Administrators,
                mask: FILE_ALL_ACCESS,
                flags: 0,
                allowed: true,
            },
            AceInspection {
                principal: Principal::Worker,
                mask: FILE_READ,
                flags: 0,
                allowed: true,
            },
        ]
    }

    #[test]
    #[ignore = "environmental: elevated Windows plus STYRN_WINDOWS_TEST_WORKER and STYRN_WINDOWS_TEST_PASSWORD"]
    fn real_windows_worker_can_read_but_cannot_mutate_or_take_over_manifest_and_receipt() {
        let worker = std::env::var("STYRN_WINDOWS_TEST_WORKER")
            .expect("STYRN_WINDOWS_TEST_WORKER must select a real unprivileged account");
        let password = std::env::var("STYRN_WINDOWS_TEST_PASSWORD")
            .expect("STYRN_WINDOWS_TEST_PASSWORD is required for worker impersonation");
        let public = std::path::PathBuf::from(
            std::env::var_os("PUBLIC").expect("Windows PUBLIC directory is required"),
        );
        let directory = public.join(format!(
            "styrn-acl-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        harden_manifest_directory(&directory, ManifestOwner::System, &worker).unwrap();
        let manifest = directory.join("machine.toml");
        std::fs::write(&manifest, "schema_version = 1\n").unwrap();
        harden_manifest_file(&manifest, ManifestOwner::System, &worker).unwrap();
        verify_manifest_security(&manifest, ManifestOwner::System, &worker, &directory).unwrap();
        let receipt = directory.join("receipt.json");
        std::fs::write(&receipt, "{\"schema_version\":1,\"entries\":[]}\n").unwrap();
        harden_manifest_file(&receipt, ManifestOwner::System, &worker).unwrap();
        verify_manifest_security(&receipt, ManifestOwner::System, &worker, &directory).unwrap();
        let receipt_lock = directory.join(".receipt.json.lock");
        drop(create_private_file(&receipt_lock, ManifestOwner::System).unwrap());
        inspect_private_acl(&receipt_lock, AclKind::Lock).unwrap();

        let replacement_directory = public.join(format!(
            "styrn-acl-replacement-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&replacement_directory).unwrap();
        let worker_sid = lookup_account_sid(&worker).unwrap();
        let worker_sid = sid_to_string(worker_sid.as_ptr().cast()).unwrap();
        apply_sddl(
            &replacement_directory,
            &format!("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{worker_sid})"),
        )
        .unwrap();
        let replacement = replacement_directory.join("replacement.toml");
        std::fs::write(&replacement, "replacement = true\n").unwrap();
        apply_sddl(
            &replacement,
            &format!("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{worker_sid})"),
        )
        .unwrap();

        let username = wide(&worker);
        let domain = wide(".");
        let mut password = wide(&password);
        let mut token = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                LogonUserW(
                    username.as_ptr(),
                    domain.as_ptr(),
                    password.as_ptr(),
                    2,
                    0,
                    &mut token,
                )
            },
            0,
            "LogonUserW failed: {}",
            io::Error::last_os_error()
        );
        password.fill(0);
        assert_ne!(unsafe { ImpersonateLoggedOnUser(token) }, 0);
        let impersonation = ImpersonationGuard(token);

        assert!(std::fs::read_to_string(&manifest).is_ok());
        assert_access_denied(std::fs::OpenOptions::new().write(true).open(&manifest));
        assert_access_denied(std::fs::remove_file(&manifest));
        assert_access_denied(std::fs::rename(&manifest, directory.join("renamed.toml")));
        assert_access_denied(replace_file(&replacement, &manifest));
        assert_access_denied(apply_sddl(
            &manifest,
            &format!("O:BAD:P(A;;FA;;;{worker_sid})"),
        ));

        assert!(std::fs::read_to_string(&receipt).is_ok());
        assert_access_denied(std::fs::OpenOptions::new().write(true).open(&receipt));
        assert_access_denied(std::fs::remove_file(&receipt));
        assert_access_denied(std::fs::rename(
            &receipt,
            directory.join("renamed-receipt.json"),
        ));
        assert_access_denied(replace_file(&replacement, &receipt));
        assert_access_denied(apply_sddl(
            &receipt,
            &format!("O:BAD:P(A;;FA;;;{worker_sid})"),
        ));
        assert_access_denied(std::fs::File::open(&receipt_lock));
        assert_access_denied(std::fs::OpenOptions::new().write(true).open(&receipt_lock));
        assert_access_denied(std::fs::remove_file(&receipt_lock));
        assert_access_denied(std::fs::rename(
            &receipt_lock,
            directory.join("renamed-receipt-lock"),
        ));
        assert_access_denied(apply_sddl(
            &receipt_lock,
            &format!("O:BAD:P(A;;FA;;;{worker_sid})"),
        ));

        drop(impersonation);
        std::fs::remove_file(manifest).unwrap();
        std::fs::remove_file(receipt).unwrap();
        std::fs::remove_file(receipt_lock).unwrap();
        std::fs::remove_dir(directory).unwrap();
        std::fs::remove_file(replacement).unwrap();
        std::fs::remove_dir(replacement_directory).unwrap();
    }

    #[test]
    #[ignore = "environmental: elevated Windows plus STYRN_WINDOWS_TEST_WORKER and STYRN_WINDOWS_TEST_PASSWORD"]
    fn real_windows_worker_cannot_access_private_staging_or_files_before_publication() {
        let worker = std::env::var("STYRN_WINDOWS_TEST_WORKER")
            .expect("STYRN_WINDOWS_TEST_WORKER must select a real unprivileged account");
        let password = std::env::var("STYRN_WINDOWS_TEST_PASSWORD")
            .expect("STYRN_WINDOWS_TEST_PASSWORD is required for worker impersonation");
        let public = std::path::PathBuf::from(
            std::env::var_os("PUBLIC").expect("Windows PUBLIC directory is required"),
        );
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let parent = public.join(format!("styrn-staging-parent-{nonce}"));
        std::fs::create_dir(&parent).unwrap();
        harden_manifest_directory(&parent, ManifestOwner::System, &worker).unwrap();

        let staging = parent.join("staging");
        create_private_manifest_staging_directory(&staging, ManifestOwner::System).unwrap();
        inspect_private_acl(&staging, AclKind::Staging).unwrap();
        assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
        let private_file = parent.join("receipt-intent.json");
        let mut private = create_private_file(&private_file, ManifestOwner::System).unwrap();
        std::io::Write::write_all(&mut private, b"private receipt intent").unwrap();
        private.sync_all().unwrap();
        drop(private);
        inspect_private_acl(&private_file, AclKind::Lock).unwrap();

        let replacement = public.join(format!("styrn-staging-replacement-{nonce}"));
        std::fs::create_dir(&replacement).unwrap();
        let worker_sid = lookup_account_sid(&worker).unwrap();
        let worker_sid = sid_to_string(worker_sid.as_ptr().cast()).unwrap();
        apply_sddl(
            &replacement,
            &format!("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{worker_sid})"),
        )
        .unwrap();

        let swap_control = public.join(format!("styrn-staging-swap-control-{nonce}"));
        std::fs::create_dir(&swap_control).unwrap();
        apply_sddl(
            &swap_control,
            &format!("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{worker_sid})"),
        )
        .unwrap();
        let control_destination = swap_control.join("destination");
        let control_replacement = swap_control.join("replacement");
        std::fs::create_dir(&control_destination).unwrap();
        std::fs::create_dir(&control_replacement).unwrap();
        let control_marker = control_replacement.join("replacement-marker");
        std::fs::write(&control_marker, b"replacement reached").unwrap();

        let username = wide(&worker);
        let domain = wide(".");
        let mut password = wide(&password);
        let mut token = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                LogonUserW(
                    username.as_ptr(),
                    domain.as_ptr(),
                    password.as_ptr(),
                    2,
                    0,
                    &mut token,
                )
            },
            0,
            "LogonUserW failed: {}",
            io::Error::last_os_error()
        );
        password.fill(0);
        assert_ne!(unsafe { ImpersonateLoggedOnUser(token) }, 0);
        let impersonation = ImpersonationGuard(token);

        open_directory_for_read(&replacement)
            .expect("worker cannot exercise the directory-open control");
        std::fs::read_dir(&replacement).expect("worker cannot exercise the directory-list control");
        let worker_control = replacement.join("worker-control");
        std::fs::write(&worker_control, b"worker-controlled")
            .expect("worker cannot exercise the directory-create control");
        let control_swap =
            attempt_delete_then_rename_directory_swap(&control_replacement, &control_destination);
        assert!(
            matches!(
                &control_swap,
                DirectorySwapOutcome::SourceRenamedIntoDestination
            ),
            "worker-writable delete-then-rename control did not complete: {control_swap:?}"
        );

        assert_access_denied_for("open staging directory", open_directory_for_read(&staging));
        assert_access_denied_for("list staging directory", std::fs::read_dir(&staging));
        assert_access_denied_for(
            "create within staging directory",
            std::fs::write(staging.join("worker-created"), b"worker-controlled"),
        );
        assert_access_denied_for(
            "rename staging directory",
            std::fs::rename(&staging, parent.join("renamed")),
        );
        assert_access_denied_for("delete staging directory", std::fs::remove_dir(&staging));
        assert_access_denied_for("read private receipt file", std::fs::read(&private_file));
        assert_access_denied_for(
            "write private receipt file",
            std::fs::OpenOptions::new().write(true).open(&private_file),
        );
        assert_access_denied_for(
            "delete private receipt file",
            std::fs::remove_file(&private_file),
        );
        assert_access_denied_for(
            "rename private receipt file",
            std::fs::rename(&private_file, parent.join("renamed-intent.json")),
        );
        assert_access_denied_for(
            "replace private receipt file",
            replace_file(&worker_control, &private_file),
        );
        match attempt_delete_then_rename_directory_swap(&replacement, &staging) {
            DirectorySwapOutcome::Blocked { step, error } => {
                assert_eq!(step, DirectorySwapStep::DeleteDestination);
                assert_eq!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied,
                    "delete-then-rename staging swap failed unexpectedly: {error}"
                );
            }
            DirectorySwapOutcome::SourceRenamedIntoDestination => {
                panic!("worker completed a delete-then-rename staging swap")
            }
        }

        drop(impersonation);
        assert!(
            staging.is_dir(),
            "delete-then-rename attempt removed the protected staging directory"
        );
        assert!(
            replacement.is_dir(),
            "replacement source moved despite the denied destination-delete step"
        );
        assert!(
            !control_replacement.exists(),
            "worker-writable control did not move its replacement source"
        );
        assert!(
            control_destination.join("replacement-marker").is_file(),
            "worker-writable control did not complete its replacement rename"
        );
        assert!(!staging.join("worker-created").exists());
        assert!(!parent.join("renamed").exists());
        assert!(private_file.is_file());
        assert!(!parent.join("renamed-intent.json").exists());

        std::fs::remove_dir(staging).unwrap();
        std::fs::remove_file(private_file).unwrap();
        std::fs::remove_dir(parent).unwrap();
        std::fs::remove_file(worker_control).unwrap();
        std::fs::remove_dir(replacement).unwrap();
        std::fs::remove_file(control_destination.join("replacement-marker")).unwrap();
        std::fs::remove_dir(control_destination).unwrap();
        std::fs::remove_dir(swap_control).unwrap();
    }

    fn assert_access_denied<T: std::fmt::Debug>(result: io::Result<T>) {
        assert_access_denied_for("worker mutation", result);
    }

    fn assert_access_denied_for<T: std::fmt::Debug>(operation: &str, result: io::Result<T>) {
        let error = match result {
            Ok(value) => panic!("{operation} unexpectedly succeeded: {value:?}"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            io::ErrorKind::PermissionDenied,
            "{operation}: {error}"
        );
    }

    #[derive(Debug)]
    enum DirectorySwapOutcome {
        SourceRenamedIntoDestination,
        Blocked {
            step: DirectorySwapStep,
            error: io::Error,
        },
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DirectorySwapStep {
        DeleteDestination,
        RenameSourceIntoDestination,
    }

    fn attempt_delete_then_rename_directory_swap(
        source: &Path,
        destination: &Path,
    ) -> DirectorySwapOutcome {
        if let Err(error) = std::fs::remove_dir(destination) {
            return DirectorySwapOutcome::Blocked {
                step: DirectorySwapStep::DeleteDestination,
                error,
            };
        }
        if let Err(error) = std::fs::rename(source, destination) {
            return DirectorySwapOutcome::Blocked {
                step: DirectorySwapStep::RenameSourceIntoDestination,
                error,
            };
        }
        DirectorySwapOutcome::SourceRenamedIntoDestination
    }

    fn open_directory_for_read(path: &Path) -> io::Result<()> {
        const GENERIC_READ: u32 = 0x8000_0000;
        const FILE_SHARE_READ: u32 = 0x1;
        const FILE_SHARE_WRITE: u32 = 0x2;
        const FILE_SHARE_DELETE: u32 = 0x4;
        const OPEN_EXISTING: u32 = 3;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const INVALID_HANDLE_VALUE: *mut c_void = -1_isize as *mut c_void;

        let path = wide_os(path);
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        unsafe {
            CloseHandle(handle);
        }
        Ok(())
    }

    struct ImpersonationGuard(*mut c_void);

    impl Drop for ImpersonationGuard {
        fn drop(&mut self) {
            unsafe {
                RevertToSelf();
                CloseHandle(self.0);
            }
        }
    }
}
