#[allow(dead_code)]
pub(crate) fn platform_name() -> &'static str {
    "windows"
}

use super::ManifestOwner;
use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

pub(super) struct ManifestDirectoryIdentity {
    volume_serial_number: u32,
    file_index: u64,
}

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
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const INVALID_FILE_ATTRIBUTES: u32 = 0xffff_ffff;
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

#[repr(C)]
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

#[derive(Clone, Copy)]
enum AclKind {
    Manifest,
    Directory,
    Lock,
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
    fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *const c_void,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: *mut c_void,
    ) -> *mut c_void;
    fn GetFileInformationByHandle(
        file: *mut c_void,
        information: *mut ByHandleFileInformation,
    ) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

pub(crate) fn replace_file(temporary: &Path, destination: &Path) -> io::Result<()> {
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
    }

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

pub(super) fn harden_manifest_lock(path: &Path, owner: ManifestOwner) -> io::Result<()> {
    require_kind(path, false)?;
    if is_test_owner(owner) {
        return Ok(());
    }
    apply_acl(path, "styrn", AclKind::Lock)?;
    inspect_acl(path, "styrn", AclKind::Lock)
}

pub(super) fn open_manifest_lock(path: &Path, owner: ManifestOwner) -> io::Result<std::fs::File> {
    let created = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path);
    let file = match created {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            harden_manifest_lock(path, owner)?;
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?
        }
        Err(error) => return Err(error),
    };
    harden_manifest_lock(path, owner)?;
    Ok(file)
}

pub(super) fn create_manifest_temporary(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
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

pub(super) fn manifest_directory_identity(
    directory: &Path,
) -> io::Result<ManifestDirectoryIdentity> {
    directory_identity(directory)
}

pub(super) fn remove_manifest_directory_if_same_and_empty(
    directory: &Path,
    identity: &ManifestDirectoryIdentity,
) -> io::Result<()> {
    let current = directory_identity(directory)?;
    if current.volume_serial_number != identity.volume_serial_number
        || current.file_index != identity.file_index
    {
        return Err(permission_denied(
            "new manifest directory changed before cleanup",
        ));
    }
    std::fs::remove_dir(directory)
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
        AclKind::Lock => "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)".to_owned(),
    }
}

fn inspect_acl(path: &Path, worker: &str, kind: AclKind) -> io::Result<()> {
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
    if dacl.is_null() || owner.is_null() {
        return Err(permission_denied(
            "manifest security descriptor is incomplete",
        ));
    }

    let administrators = well_known_sid(WIN_BUILTIN_ADMINISTRATORS_SID)?;
    let system = well_known_sid(WIN_LOCAL_SYSTEM_SID)?;
    let worker = lookup_account_sid(worker)?;
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let inspection = AclInspection {
        owner_is_administrators: unsafe { EqualSid(owner, administrators.as_ptr().cast()) } != 0,
        dacl_is_protected: control & SE_DACL_PROTECTED != 0,
        entries: inspect_aces(dacl, &system, &administrators, &worker)?,
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
        return Err(permission_denied("styrn worker owns a manifest ancestor"));
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
        AclKind::Lock => {}
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

fn directory_identity(directory: &Path) -> io::Result<ManifestDirectoryIdentity> {
    require_kind(directory, true)?;
    let wide_path = wide_os(directory);
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == (-1_isize as *mut c_void) {
        return Err(io::Error::last_os_error());
    }
    let handle = OwnedHandle(handle);
    let mut information = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
    if unsafe { GetFileInformationByHandle(handle.0, information.as_mut_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let information = unsafe { information.assume_init() };
    if information.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(permission_denied(
            "manifest security path crosses a reparse point",
        ));
    }
    Ok(ManifestDirectoryIdentity {
        volume_serial_number: information.volume_serial_number,
        file_index: (u64::from(information.file_index_high) << 32)
            | u64::from(information.file_index_low),
    })
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

struct OwnedHandle(*mut c_void);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

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
    #[ignore = "environmental: elevated Windows, real styrn account, and STYRN_WINDOWS_TEST_PASSWORD"]
    fn real_windows_worker_can_read_but_cannot_write_delete_rename_or_replace() {
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
        harden_manifest_directory(&directory, ManifestOwner::System, "styrn").unwrap();
        let manifest = directory.join("machine.toml");
        std::fs::write(&manifest, "schema_version = 1\n").unwrap();
        harden_manifest_file(&manifest, ManifestOwner::System, "styrn").unwrap();
        verify_manifest_security(&manifest, ManifestOwner::System, "styrn", &directory).unwrap();

        let replacement_directory = public.join(format!(
            "styrn-acl-replacement-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&replacement_directory).unwrap();
        let worker_sid = lookup_account_sid("styrn").unwrap();
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

        let username = wide("styrn");
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

        drop(impersonation);
        std::fs::remove_file(manifest).unwrap();
        std::fs::remove_dir(directory).unwrap();
        std::fs::remove_file(replacement).unwrap();
        std::fs::remove_dir(replacement_directory).unwrap();
    }

    fn assert_access_denied<T: std::fmt::Debug>(result: io::Result<T>) {
        let error = result.expect_err("worker mutation unexpectedly succeeded");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
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
